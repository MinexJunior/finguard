add_executable(test_process_monitor
    cpp/test_process_monitor.cpp
)

target_link_libraries(test_process_monitor PRIVATE
    finguard_core
)

add_test(NAME ProcessMonitorTest COMMAND test_process_monitor)

add_executable(test_pe_analyzer
    cpp/test_pe_analyzer.cpp
)

target_link_libraries(test_pe_analyzer PRIVATE
    finguard_core
)

add_test(NAME PeAnalyzerTest COMMAND test_pe_analyzer)

add_executable(test_risk_engine
    cpp/test_risk_engine.cpp
)

target_link_libraries(test_risk_engine PRIVATE
    finguard_core
)

add_test(NAME RiskEngineTest COMMAND test_risk_engine)

add_executable(test_behavior_monitor
    cpp/test_behavior_monitor.cpp
)

target_link_libraries(test_behavior_monitor PRIVATE
    finguard_core
)

add_test(NAME BehaviorMonitorTest COMMAND test_behavior_monitor)

add_executable(test_evaluation_t1_t10
    cpp/test_evaluation_t1_t10.cpp
)

target_link_libraries(test_evaluation_t1_t10 PRIVATE
    finguard_core
)

add_test(NAME EvaluationT1toT10Test COMMAND test_evaluation_t1_t10)

