-- Trusted checker fixture. The runner applies this migration after C# image build.
CREATE SCHEMA IF NOT EXISTS probe_b55d733620;

CREATE TABLE IF NOT EXISTS probe_b55d733620.effect_929740a8c2 (
    execution_id text PRIMARY KEY,
    business_value text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION probe_b55d733620.execute_fda552339a(
    p_context jsonb,
    p_payload jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, probe_b55d733620
AS $fn$
DECLARE
    v_execution_id text := p_context ->> 'executionId';
    v_mode text := p_payload ->> 'mode_d566e409';
    v_value text := p_payload ->> 'value_c6e4ac8e';
    v_outcome text := 'ROUTE_SIGNAL_72125C4E';
    v_meta jsonb := jsonb_build_object(
        'correlationId', p_context ->> 'correlationId',
        'actionVersion', 1,
        'executionId', v_execution_id
    );
BEGIN
    INSERT INTO probe_b55d733620.effect_929740a8c2(execution_id, business_value)
    VALUES (v_execution_id, v_value)
    ON CONFLICT (execution_id) DO NOTHING;

    IF v_mode = 'signal_aecd1de' THEN
        v_outcome := 'ROUTE_SIGNAL_72125C4E';
    ELSIF v_mode = 'retry_bab420a' THEN
        RETURN jsonb_build_object(
            'status', 'error',
            'code', 'fixture.retry_a7dfc8eb',
            'message', 'forced retryable public error',
            'retryable', true,
            'details', '{}'::jsonb,
            'meta', v_meta
        );
    ELSIF v_mode = 'error_210e938' THEN
        RETURN jsonb_build_object(
            'status', 'error',
            'code', 'fixture.error_09b64e2f',
            'message', 'forced non-retryable public error',
            'retryable', false,
            'details', '{}'::jsonb,
            'meta', v_meta
        );
    ELSIF v_mode = 'unknown_8b825c1' THEN
        v_outcome := 'UNDECLARED_7CD21CE6';
    ELSIF v_mode = 'manual_f43d11c' THEN
        v_outcome := 'ROUTE_MANUAL_503E0EA7';
    END IF;

    IF v_mode = 'invalid_1c3f7e6' THEN
        RETURN jsonb_build_object(
            'status', 'ok',
            'outcome', v_outcome,
            'result', jsonb_build_object(
                'stored_8a9210a8', 'not-a-boolean',
                'revision_5525dad9', 1,
                'echo_c7db0f6e', v_value,
                'execution_b11f28c9', v_execution_id
            ),
            'meta', v_meta
        );
    END IF;

    RETURN jsonb_build_object(
        'status', 'ok',
        'outcome', v_outcome,
        'result', jsonb_build_object(
            'stored_8a9210a8', true,
            'revision_5525dad9', 1,
            'echo_c7db0f6e', v_value,
            'execution_b11f28c9', v_execution_id
        ),
        'meta', v_meta
    );
END;
$fn$;
