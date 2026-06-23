"""
NetSight - Flask Application Entry Point
================================================
Main Flask application that ties together all backend modules,
serves the web dashboard, and exposes REST API endpoints.

Purpose:
    - Initialize all backend modules (database, sniffer, analyzers, detectors)
    - Serve HTML dashboard pages
    - Expose JSON API endpoints for frontend consumption
    - Manage background threads for detection engines
    - Handle report generation and file downloads
    - Provide capture start/stop control

Routes (Pages):
    /               → Dashboard
    /traffic        → Live Traffic
    /alerts         → Security Alerts
    /analytics      → Analytics & Charts
    /reports        → Report Generation

API Endpoints (JSON):
    GET  /api/dashboard           → Dashboard stats
    GET  /api/traffic             → Recent traffic logs
    GET  /api/traffic/stats       → Traffic statistics
    GET  /api/alerts              → Alerts list (with filters)
    POST /api/alerts/<id>/resolve → Resolve an alert
    GET  /api/anomalies           → AI anomaly results
    POST /api/reports/generate    → Generate report
    GET  /api/reports             → List reports
    GET  /api/reports/<filename>  → Download report file
    POST /api/capture/start       → Start packet capture
    POST /api/capture/stop        → Stop packet capture
    GET  /api/capture/status      → Capture engine status
"""

import os
import threading
import time
import atexit
from flask import Flask, render_template, jsonify, request, send_from_directory

from config import (
    FLASK_HOST, FLASK_PORT, FLASK_DEBUG, SECRET_KEY,
    REPORTS_DIR, DETECTION_INTERVAL, AI_ANALYSIS_INTERVAL,
    STATS_UPDATE_INTERVAL, CLEANUP_INTERVAL
)

# ============================================================
# FLASK APP INITIALIZATION
# ============================================================
app = Flask(__name__)
app.secret_key = SECRET_KEY

# ============================================================
# BACKEND MODULE INITIALIZATION
# ============================================================
from backend.logger import get_system_logger
logger = get_system_logger('App')

logger.info('=' * 60)
logger.info('NetSight Starting...')
logger.info('=' * 60)

# Initialize database
from backend.database import init_db
init_db()
logger.info('Database initialized')

# Import backend modules
from backend.packet_sniffer import PacketSniffer
from backend.traffic_analyzer import TrafficAnalyzer
from backend.port_scan_detector import PortScanDetector
from backend.bruteforce_detector import BruteForceDetector
from backend.suspicious_activity_detector import SuspiciousActivityDetector
from backend.ai_detector import AIDetector
from backend.alert_manager import alert_manager
from backend.report_generator import ReportGenerator
from backend import database as db
from backend.dns_resolver import dns_resolver

# Create module instances
sniffer = PacketSniffer()
analyzer = TrafficAnalyzer()
port_scan_detector = PortScanDetector()
brute_force_detector = BruteForceDetector()
suspicious_detector = SuspiciousActivityDetector()
ai_detector = AIDetector()
report_generator = ReportGenerator()

# Register packet callbacks — detection engines receive every packet
sniffer.register_callback(analyzer.process_packet)
sniffer.register_callback(port_scan_detector.process_packet)
sniffer.register_callback(brute_force_detector.process_packet)
sniffer.register_callback(suspicious_detector.process_packet)

logger.info('All backend modules initialized')

# ============================================================
# BACKGROUND SCHEDULER
# ============================================================
_scheduler_running = False


def background_scheduler():
    """
    Background thread that periodically runs:
    - Traffic stats computation (every 1s)
    - Detection engine analysis (every 5s)
    - AI anomaly detection (every 30s)
    - Data cleanup (every 1h)
    """
    global _scheduler_running
    _scheduler_running = True

    last_stats = 0
    last_detection = 0
    last_ai = 0
    last_cleanup = 0
    last_stats_save = 0
    last_suspicious_cleanup = 0

    logger.info('Background scheduler started')

    while _scheduler_running:
        try:
            now = time.time()

            # --- Stats update (every 1s) ---
            if now - last_stats >= STATS_UPDATE_INTERVAL:
                analyzer.compute_stats()
                last_stats = now

            # --- Save stats snapshot (every 5s) ---
            if now - last_stats_save >= 5:
                analyzer.save_stats_snapshot()
                last_stats_save = now

            # --- Detection analysis (every 5s) ---
            if now - last_detection >= DETECTION_INTERVAL:
                stats = analyzer.get_stats()
                pps = stats.get('packets_per_second', 0)

                # Run suspicious activity analysis
                suspicious_detector.analyze(current_pps=pps)

                # Cleanup expired tracking data
                port_scan_detector.cleanup()
                brute_force_detector.cleanup()

                last_detection = now

            # --- Suspicious Activity Cleanup (every 60s) ---
            if now - last_suspicious_cleanup >= 60:
                suspicious_detector.cleanup()
                last_suspicious_cleanup = now

            # --- AI analysis (every 30s) ---
            if now - last_ai >= AI_ANALYSIS_INTERVAL:
                features = analyzer.get_ai_features()
                prediction = ai_detector.predict(features)

                if prediction and prediction.get('is_anomaly'):
                    alert_manager.create_ai_anomaly_alert(
                        source_ip='AI_ENGINE',
                        threat_score=prediction['threat_score'],
                        classification=prediction['classification'],
                        details=str(prediction.get('features', {}))
                    )

                last_ai = now

            # --- Cleanup (every 1h) ---
            if now - last_cleanup >= CLEANUP_INTERVAL:
                db.cleanup_old_records()
                alert_manager.cleanup_dedup_cache()
                last_cleanup = now

            time.sleep(0.5)

        except Exception as e:
            logger.error('Scheduler error: %s', str(e))
            time.sleep(1)

    logger.info('Background scheduler stopped')


# Start scheduler thread
_scheduler_thread = threading.Thread(
    target=background_scheduler, daemon=True, name='Scheduler'
)
_scheduler_thread.start()

# Auto-start capture
sniffer.start_capture()
logger.info('Auto-started packet capture')


# ============================================================
# CLEANUP ON SHUTDOWN
# ============================================================
def shutdown():
    """Clean shutdown of all background processes."""
    global _scheduler_running
    _scheduler_running = False
    sniffer.stop_capture()
    logger.info('NetSight shutdown complete')


atexit.register(shutdown)


# ============================================================
# PAGE ROUTES
# ============================================================
@app.route('/')
def dashboard_page():
    """Main dashboard page."""
    return render_template('dashboard.html', active_page='dashboard')


@app.route('/traffic')
def traffic_page():
    """Live traffic viewer page."""
    return render_template('traffic.html', active_page='traffic')


@app.route('/alerts')
def alerts_page():
    """Security alerts page."""
    return render_template('alerts.html', active_page='alerts')


@app.route('/analytics')
def analytics_page():
    """Analytics and charts page."""
    return render_template('analytics.html', active_page='analytics')


@app.route('/reports')
def reports_page():
    """Reports page."""
    return render_template('reports.html', active_page='reports')


# ============================================================
# API: DASHBOARD
# ============================================================
@app.route('/api/dashboard')
def api_dashboard():
    """
    Get aggregated dashboard statistics.

    Returns JSON with: total_packets, active_connections, total_alerts,
    unresolved_alerts, threat_score, ai_status, protocol_distribution,
    recent_alerts, stats_history, packets_per_second, unique_ips
    """
    try:
        db_stats = db.get_dashboard_stats()
        traffic_stats = analyzer.get_stats()
        ai_status = ai_detector.get_status()
        suspicious_stats = suspicious_detector.get_stats()
        recent_alerts = db.get_alerts(limit=10)
        resolved_alerts = []
        for alert in recent_alerts:
            a = dict(alert)
            if a.get('source_ip'):
                a['source_ip'] = dns_resolver.get_display_name(a['source_ip'])
            if a.get('destination_ip'):
                a['destination_ip'] = dns_resolver.get_display_name(a['destination_ip'])
            resolved_alerts.append(a)

        stats_history = analyzer.get_stats_history(limit=60)
        resolved_history = []
        for hist_item in stats_history:
            h = dict(hist_item)
            if 'top_source_ips' in h:
                resolved_ips = []
                for item in h['top_source_ips']:
                    resolved_ips.append({
                        'ip': dns_resolver.get_display_name(item['ip']),
                        'count': item['count']
                    })
                h['top_source_ips'] = resolved_ips
            resolved_history.append(h)

        # Get AI classification
        ai_classification = 'Normal'
        ai_threat = 0
        if ai_status.get('last_prediction'):
            ai_classification = ai_status['last_prediction'].get('classification', 'Normal')
            ai_threat = ai_status['last_prediction'].get('threat_score', 0)

        # Combined threat score
        threat_score = max(
            suspicious_stats.get('current_threat_score', 0),
            ai_threat
        )

        return jsonify({
            'total_packets': db_stats.get('total_packets', 0),
            'recent_packets': db_stats.get('recent_packets', 0),
            'active_connections': traffic_stats.get('active_connections', 0),
            'total_alerts': db_stats.get('total_alerts', 0),
            'unresolved_alerts': db_stats.get('unresolved_alerts', 0),
            'threat_score': round(threat_score, 1),
            'packets_per_second': traffic_stats.get('packets_per_second', 0),
            'bytes_per_second': traffic_stats.get('bytes_per_second', 0),
            'unique_ips': traffic_stats.get('unique_src_ips', 0),
            'protocol_distribution': traffic_stats.get('protocol_distribution', {}),
            'ai_status': {
                'status': ai_status.get('status', 'unknown'),
                'classification': ai_classification,
                'threat_score': ai_threat,
                'predictions_made': ai_status.get('predictions_made', 0),
                'anomalies_detected': ai_status.get('anomalies_detected', 0),
                'is_trained': ai_status.get('is_trained', False)
            },
            'recent_alerts': resolved_alerts,
            'stats_history': resolved_history,
            'alert_counts': db_stats.get('alert_counts', {})
        })
    except Exception as e:
        logger.error('API dashboard error: %s', str(e))
        return jsonify({'error': str(e)}), 500


# ============================================================
# API: TRAFFIC
# ============================================================
@app.route('/api/traffic')
def api_traffic():
    """
    Get recent traffic logs with optional filtering.

    Query params: limit (int), offset (int), protocol (str), src_ip (str)
    """
    try:
        limit = min(int(request.args.get('limit', 100)), 500)
        offset = int(request.args.get('offset', 0))
        protocol = request.args.get('protocol', '').strip() or None
        src_ip = request.args.get('src_ip', '').strip() or None
        if src_ip and '(' in src_ip and src_ip.endswith(')'):
            import re
            match = re.search(r'\(([^)]+)\)', src_ip)
            if match:
                src_ip = match.group(1).strip()

        packets = db.get_recent_traffic(
            limit=limit, offset=offset,
            protocol=protocol, src_ip=src_ip
        )
        total = db.get_traffic_count()

        resolved_packets = []
        for p in packets:
            pkt = dict(p)
            if pkt.get('src_ip'):
                pkt['src_ip'] = dns_resolver.get_display_name(pkt['src_ip'])
            if pkt.get('dst_ip'):
                pkt['dst_ip'] = dns_resolver.get_display_name(pkt['dst_ip'])
            resolved_packets.append(pkt)

        return jsonify({
            'packets': resolved_packets,
            'total_count': total,
            'limit': limit,
            'offset': offset
        })
    except Exception as e:
        logger.error('API traffic error: %s', str(e))
        return jsonify({'error': str(e)}), 500


@app.route('/api/traffic/stats')
def api_traffic_stats():
    """
    Get real-time traffic statistics and history.
    """
    try:
        stats = dict(analyzer.get_stats())
        history = analyzer.get_stats_history(limit=60)

        if 'top_source_ips' in stats:
            resolved_ips = []
            for item in stats['top_source_ips']:
                resolved_ips.append({
                    'ip': dns_resolver.get_display_name(item['ip']),
                    'count': item['count']
                })
            stats['top_source_ips'] = resolved_ips

        resolved_history = []
        for hist_item in history:
            h = dict(hist_item)
            if 'top_source_ips' in h:
                resolved_ips = []
                for item in h['top_source_ips']:
                    resolved_ips.append({
                        'ip': dns_resolver.get_display_name(item['ip']),
                        'count': item['count']
                    })
                h['top_source_ips'] = resolved_ips
            resolved_history.append(h)

        return jsonify({
            **stats,
            'history': resolved_history
        })
    except Exception as e:
        logger.error('API traffic stats error: %s', str(e))
        return jsonify({'error': str(e)}), 500


# ============================================================
# API: ALERTS
# ============================================================
@app.route('/api/alerts')
def api_alerts():
    """
    Get security alerts with optional filtering.

    Query params: limit (int), type (str), severity (str)
    """
    try:
        limit = min(int(request.args.get('limit', 100)), 500)
        alert_type = request.args.get('type', '').strip() or None
        severity = request.args.get('severity', '').strip() or None

        alerts = db.get_alerts(
            limit=limit,
            alert_type=alert_type,
            severity=severity
        )

        resolved_alerts = []
        for alert in alerts:
            a = dict(alert)
            if a.get('source_ip'):
                a['source_ip'] = dns_resolver.get_display_name(a['source_ip'])
            if a.get('destination_ip'):
                a['destination_ip'] = dns_resolver.get_display_name(a['destination_ip'])
            resolved_alerts.append(a)

        return jsonify({
            'alerts': resolved_alerts,
            'count': len(resolved_alerts)
        })
    except Exception as e:
        logger.error('API alerts error: %s', str(e))
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
def api_resolve_alert(alert_id):
    """Resolve a specific alert by ID."""
    try:
        success = db.resolve_alert(alert_id)
        return jsonify({
            'success': success,
            'alert_id': alert_id
        })
    except Exception as e:
        logger.error('API resolve alert error: %s', str(e))
        return jsonify({'error': str(e)}), 500


# ============================================================
# API: ANOMALIES
# ============================================================
@app.route('/api/anomalies')
def api_anomalies():
    """Get AI anomaly detection results."""
    try:
        anomalies = db.get_recent_anomalies(limit=50)
        ai_status = ai_detector.get_status()

        return jsonify({
            'anomalies': anomalies,
            'ai_status': ai_status
        })
    except Exception as e:
        logger.error('API anomalies error: %s', str(e))
        return jsonify({'error': str(e)}), 500


# ============================================================
# API: AI CONTROL
# ============================================================
@app.route('/api/ai/retrain', methods=['POST'])
def api_retrain_ai():
    """Trigger background retraining of the AI model on historical db logs."""
    try:
        from backend.ai_detector import ML_AVAILABLE
        if not ML_AVAILABLE:
            return jsonify({'success': False, 'error': 'scikit-learn is not available on this system'}), 400

        def run_retrain():
            ai_detector.retrain_from_db()

        thread = threading.Thread(target=run_retrain, name='AIRetrainWorker')
        thread.start()

        return jsonify({
            'success': True,
            'message': 'AI model retraining initiated in the background'
        })
    except Exception as e:
        logger.error('API AI retrain error: %s', str(e))
        return jsonify({'error': str(e)}), 500


# ============================================================
# API: REPORTS
# ============================================================
@app.route('/api/reports/generate', methods=['POST'])
def api_generate_report():
    """Generate a new security report (PDF + CSV)."""
    try:
        hours = int(request.args.get('hours', 24))
        result = report_generator.generate_daily_report(hours=hours)

        return jsonify({
            'success': True,
            'files': result.get('files', []),
            'summary': result.get('summary', {})
        })
    except Exception as e:
        logger.error('API report generation error: %s', str(e))
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports')
def api_list_reports():
    """List all available generated reports."""
    try:
        reports = report_generator.get_available_reports()
        return jsonify({'reports': reports})
    except Exception as e:
        logger.error('API list reports error: %s', str(e))
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/<filename>')
def api_download_report(filename):
    """Download a specific report file."""
    try:
        # Security: sanitize filename
        safe_filename = os.path.basename(filename)
        if not safe_filename.startswith('report_'):
            return jsonify({'error': 'Invalid filename'}), 400

        return send_from_directory(
            REPORTS_DIR, safe_filename,
            as_attachment=True
        )
    except FileNotFoundError:
        return jsonify({'error': 'Report not found'}), 404
    except Exception as e:
        logger.error('API download report error: %s', str(e))
        return jsonify({'error': str(e)}), 500


# ============================================================
# API: CAPTURE CONTROL
# ============================================================
@app.route('/api/capture/start', methods=['POST'])
def api_start_capture():
    """Start packet capture."""
    try:
        status = sniffer.start_capture()
        return jsonify(status)
    except Exception as e:
        logger.error('API start capture error: %s', str(e))
        return jsonify({'error': str(e)}), 500


@app.route('/api/capture/stop', methods=['POST'])
def api_stop_capture():
    """Stop packet capture."""
    try:
        status = sniffer.stop_capture()
        return jsonify(status)
    except Exception as e:
        logger.error('API stop capture error: %s', str(e))
        return jsonify({'error': str(e)}), 500


@app.route('/api/capture/status')
def api_capture_status():
    """Get current capture engine status."""
    try:
        status = sniffer.get_status()
        return jsonify(status)
    except Exception as e:
        logger.error('API capture status error: %s', str(e))
        return jsonify({'error': str(e)}), 500


# ============================================================
# ERROR HANDLERS
# ============================================================
@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors."""
    return jsonify({'error': 'Internal server error'}), 500


# ============================================================
# MAIN ENTRY POINT
# ============================================================
if __name__ == '__main__':
    logger.info('Starting Flask server on %s:%d', FLASK_HOST, FLASK_PORT)
    logger.info('Dashboard: http://localhost:%d', FLASK_PORT)
    logger.info('=' * 60)

    app.run(
        host=FLASK_HOST,
        port=FLASK_PORT,
        debug=FLASK_DEBUG,
        use_reloader=False  # Disable reloader to prevent duplicate threads
    )
