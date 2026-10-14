import sys
import os
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

def main():
    print("=" * 60)
    print("  AI Sentinel — Suite Verification Runner")
    print("=" * 60)

    try:
        print("\n1. Testing Monitoring Module...")
        import tests.test_monitoring as tm
        tm.test_get_proc_count()
        tm.test_get_top_process()
        tm.test_is_process_currently_running()
        tm.test_disk_anchor_and_os_process_immunity()
        print("   -> PASSED")

        print("\n2. Testing Feature Engineering Module...")
        import tests.test_features as tf
        tf.test_engineer_features_structure()
        tf.test_cpu_delta_calculation()
        tf.test_engineer_features_empty_and_missing_columns()
        print("   -> PASSED")

        print("\n3. Testing Anomaly Detection & Predictor Module...")
        import tests.test_anomaly_detection as ta
        ta.test_model_loading()
        ta.test_predictor_evaluation()
        ta.test_ml_score_state_classification()
        print("   -> PASSED")

        print("\n4. Testing Attribution Regression Suite (SQLSERVR / NOTION High RAM No False Alarm)...")
        import tests.test_attribution_regression as tar
        tar.test_high_ram_normal_ml_score_no_false_critical()
        tar.test_high_cpu_normal_ml_score_no_false_critical()
        tar.test_genuine_ml_score_anomaly_triggers_critical()
        print("   -> PASSED")

        print("\n5. Testing Personal Model Lifecycle...")
        import tests.test_personal_model as tp
        tp.test_personal_model_lifecycle_and_validation()
        tp.test_corrupted_model_validation()
        print("   -> PASSED")

        print("\n6. Testing Security Audit Database & Model Event Logs...")
        import tests.test_audit_db as td
        td.test_audit_db_persistence_and_deduplication()
        td.test_model_event_logging()
        print("   -> PASSED")

        print("\n7. Testing Retraining Lifecycle & Continuous Telemetry Dataset...")
        import tests.test_retraining_lifecycle as tr
        tr.test_retraining_lifecycle_and_continuous_dataset()
        print("   -> PASSED")

        print("\n8. Testing Anomaly Notification, Real-Time SSE Broker, Bottom-Right Toast, Ignore & Kill Actions...")
        import tests.test_anomaly_notification as tan
        tan.test_get_process_info_structure()
        tan.test_known_anomaly_ignore_and_whitelist_logging()
        tan.test_unknown_anomaly_kill_logging()
        tan.test_protected_process_kill_immunity()
        tan.test_snooze_alert_behavior()
        tan.test_realtime_broker_normal_activity_zero_events()
        tan.test_realtime_broker_anomaly_detection_payload()
        tan.test_realtime_broker_deduplication_cooldown()
        tan.test_realtime_sse_server_streaming_and_reconnection()
        print("   -> PASSED")

        print("\n9. Testing Robust Windows System Process Allowlist Engine...")
        import tests.test_allowlist as tal
        tal.test_canonical_system_processes_defined()
        tal.test_normal_activity_system_process_suppressed()
        tal.test_high_cpu_resource_anomaly_triggers_alert()
        tal.test_masquerading_untrusted_path_not_trusted()
        tal.test_unknown_process_eligible_for_detection()
        tal.test_predictor_integration_with_allowlist()
        tal.test_suppressed_alerts_logged_in_audit_db()
        tal.test_realtime_broker_publishes_genuine_and_resource_anomalies()
        tal.test_protected_processes_termination_immunity()
        print("   -> PASSED")

        print("\n" + "=" * 60)
        print("  ALL VERIFICATION TESTS PASSED SUCCESSFULLY!")
        print("=" * 60)

    except Exception as e:
        print(f"\n[FAIL] TEST FAILED: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
