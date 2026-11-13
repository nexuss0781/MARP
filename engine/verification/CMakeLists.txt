# Frama-C/ACSL Verification Build Configuration
# This is included by the main CMakeLists.txt when formal verification is enabled

# ──────────────────────────────────────────────────────────────
# Frama-C Detection
# ──────────────────────────────────────────────────────────────

find_program(FRAMAC frama-c)
find_program(WHY3 why3)
find_program(ALT_ERGO alt-ergo)
find_program(Z3 z3)
find_program(CVC5 cvc5)

if(FRAMAC AND WHY3 AND (ALT_ERGO OR Z3 OR CVC5))
    set(FRAMAC_AVAILABLE TRUE)
    message(STATUS "Frama-C found: ${FRAMAC}")
    message(STATUS "Why3 found: ${WHY3}")
    if(ALT_ERGO) message(STATUS "Alt-Ergo found: ${ALT_ERGO}") endif()
    if(Z3) message(STATUS "Z3 found: ${Z3}") endif()
    if(CVC5) message(STATUS "CVC5 found: ${CVC5}") endif()
else()
    set(FRAMAC_AVAILABLE FALSE)
    message(WARNING "Frama-C or provers not found. Install frama-c, why3, alt-ergo, z3, cvc5 for formal verification.")
endif()

# ──────────────────────────────────────────────────────────────
# Verification Targets
# ──────────────────────────────────────────────────────────────

if(FRAMAC_AVAILABLE)
    # Math core verification
    add_custom_target(verify_math_core
        COMMAND ${FRAMAC}
            -wp
            -wp-prover=alt-ergo,z3,cvc5
            -wp-timeout=60
            -wp-par=4
            -wp-out=verification/math_core_wp
            ${CMAKE_CURRENT_SOURCE_DIR}/math_core.acsl
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Verifying math core with Frama-C/WP"
    )

    # Container verification
    add_custom_target(verify_container
        COMMAND ${FRAMAC}
            -wp
            -wp-prover=alt-ergo,z3,cvc5
            -wp-timeout=120
            -wp-par=4
            -wp-out=verification/container_wp
            ${CMAKE_CURRENT_SOURCE_DIR}/container.acsl
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Verifying container format with Frama-C/WP"
    )

    # Combined verification
    add_custom_target(verify_all
        DEPENDS verify_math_core verify_container
        COMMENT "Running all formal verifications"
    )

    # Value analysis (abstract interpretation)
    add_custom_target(verify_value
        COMMAND ${FRAMAC}
            -val
            -val-builtins-auto
            -val-use-spec
            -val-show-progress
            ${CMAKE_CURRENT_SOURCE_DIR}/../src/math_core.c
            ${CMAKE_CURRENT_SOURCE_DIR}/../src/crypto.c
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running Frama-C value analysis"
    )

    # Impact analysis
    add_custom_target(verify_impact
        COMMAND ${FRAMAC}
            -impact
            -main main
            ${CMAKE_CURRENT_SOURCE_DIR}/../src/
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running Frama-C impact analysis"
    )

    message(STATUS "Formal verification targets: verify_math_core, verify_container, verify_all, verify_value, verify_impact")
else()
    add_custom_target(verify_all
        COMMAND echo "Frama-C not available, skipping formal verification"
        COMMENT "Frama-C not available"
    )
endif()