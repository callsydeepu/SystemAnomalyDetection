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

        print("\n" + "=" * 60)
        print("  ALL VERIFICATION TESTS PASSED SUCCESSFULLY!")
        print("=" * 60)

    except Exception as e:
        print(f"\n[FAIL] TEST FAILED: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
