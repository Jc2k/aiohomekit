"""Tests for format_characteristic_list function in IP pairing."""

from aiohomekit.controller.ip.pairing import format_characteristic_list


def test_format_characteristic_list_normal_response() -> None:
    """Test normal response with characteristic values."""
    response = {
        "characteristics": [
            {"aid": 1, "iid": 2, "value": 23.5},
            {"aid": 1, "iid": 3, "value": "test"},
            {"aid": 2, "iid": 4, "value": True},
        ]
    }
    result = format_characteristic_list(response)

    assert len(result) == 3
    assert result[(1, 2)] == {"value": 23.5}
    assert result[(1, 3)] == {"value": "test"}
    assert result[(2, 4)] == {"value": True}


def test_format_characteristic_list_success_status_removed() -> None:
    """Test that status=0 is removed from successful responses."""
    response = {
        "characteristics": [
            {"aid": 1, "iid": 2, "value": 23.5, "status": 0},
            {"aid": 1, "iid": 3, "value": "test"},
        ]
    }
    result = format_characteristic_list(response)

    assert result[(1, 2)] == {"value": 23.5}  # status=0 should be removed
    assert "status" not in result[(1, 2)]
    assert result[(1, 3)] == {"value": "test"}


def test_format_characteristic_list_individual_errors() -> None:
    """Test response with individual characteristic errors."""
    response = {
        "characteristics": [
            {"aid": 1, "iid": 2, "value": 23.5},
            {"aid": 1, "iid": 3, "status": -70402},
            {"aid": 2, "iid": 4, "status": -70404},
        ]
    }
    result = format_characteristic_list(response)

    assert result[(1, 2)] == {"value": 23.5}
    assert result[(1, 3)]["status"] == -70402
    assert "description" in result[(1, 3)]
    assert result[(2, 4)]["status"] == -70404
    assert "description" in result[(2, 4)]


def test_format_characteristic_list_global_error_no_requested() -> None:
    """Test global error response without knowing what was requested."""
    response = {"status": -70407}
    result = format_characteristic_list(response)

    assert result == {}


def test_format_characteristic_list_global_error_with_requested() -> None:
    """Test global error response with requested characteristics."""
    response = {"status": -70407}
    requested = {(1, 2), (1, 3), (2, 4)}

    result = format_characteristic_list(response, requested)

    assert len(result) == 3
    for aid, iid in requested:
        assert (aid, iid) in result
        assert result[(aid, iid)]["status"] == -70407
        assert "description" in result[(aid, iid)]
        assert "Out of resources" in result[(aid, iid)]["description"]


def test_format_characteristic_list_various_global_errors() -> None:
    """Test different global error status codes."""
    test_cases = [
        (-70401, "Request denied due to insufficient privileges"),
        (-70402, "Unable to communicate"),
        (-70403, "Resource is busy"),
        (-70408, "Operation timed out"),
        (-70409, "Resource does not exist"),
    ]

    for status, expected_desc_part in test_cases:
        response = {"status": status}
        requested = {(1, 2)}

        result = format_characteristic_list(response, requested)

        assert result[(1, 2)]["status"] == status
        assert expected_desc_part in result[(1, 2)]["description"]


def test_format_characteristic_list_empty_array() -> None:
    """Test response with empty characteristics array."""
    response = {"characteristics": []}
    result = format_characteristic_list(response)

    assert result == {}


def test_format_characteristic_list_mixed_success_failure() -> None:
    """Test response with mix of successful and failed characteristics."""
    response = {
        "characteristics": [
            {"aid": 1, "iid": 2, "value": 100, "status": 0},
            {"aid": 1, "iid": 3, "status": -70410},
            {"aid": 2, "iid": 4, "value": "OK"},
        ]
    }
    result = format_characteristic_list(response)

    assert result[(1, 2)] == {"value": 100}
    assert "status" not in result[(1, 2)]
    assert result[(1, 3)]["status"] == -70410
    assert "value" not in result[(1, 3)]
    assert result[(2, 4)] == {"value": "OK"}


def test_format_characteristic_list_large_request_global_error() -> None:
    """Test global error with large number of requested characteristics (like the real issue)."""
    # Simulate the actual scenario from the logs
    response = {"status": -70407}

    # Create a large set of requested characteristics similar to the actual error
    requested = set()
    for aid in range(1, 8):  # 7 accessories
        for iid in range(3, 20):  # Multiple characteristics each
            requested.add((aid, iid))

    result = format_characteristic_list(response, requested)

    assert len(result) == len(requested)
    for char_id in requested:
        assert char_id in result
        assert result[char_id]["status"] == -70407
        assert "Out of resources" in result[char_id]["description"]


def test_format_characteristic_list_status_zero_only() -> None:
    """Test response where all characteristics have status=0 (success)."""
    response = {
        "characteristics": [
            {"aid": 1, "iid": 2, "status": 0},
            {"aid": 1, "iid": 3, "status": 0},
        ]
    }
    result = format_characteristic_list(response)

    # Status=0 should be removed, leaving empty dicts
    assert result[(1, 2)] == {}
    assert result[(1, 3)] == {}


def test_format_characteristic_list_malformed_characteristics() -> None:
    """Test handling of malformed characteristics missing aid or iid."""
    response = {
        "characteristics": [
            {"aid": 1, "iid": 2, "value": 23.5},
            {"iid": 3, "value": "missing aid"},  # Missing aid
            {"aid": 2, "value": "missing iid"},  # Missing iid
            {"value": "missing both"},  # Missing both aid and iid
            {"aid": 1, "iid": 4, "value": 100},
        ]
    }
    result = format_characteristic_list(response)

    # Should only have the valid characteristics
    assert len(result) == 2
    assert result[(1, 2)] == {"value": 23.5}
    assert result[(1, 4)] == {"value": 100}
    # Malformed ones should be skipped


def test_format_characteristic_list_global_error_with_partial_data() -> None:
    """Test global error with some characteristics present."""
    # Device returns global error but also includes some successful characteristics
    response = {
        "status": -70407,
        "characteristics": [
            {"aid": 1, "iid": 2, "value": 23.5},
            {"aid": 1, "iid": 3, "status": -70402},
        ],
    }
    requested = {(1, 2), (1, 3), (2, 4), (2, 5)}

    result = format_characteristic_list(response, requested)

    # Should have all 4 requested characteristics
    assert len(result) == 4

    # The ones in the response should use their actual data
    assert result[(1, 2)] == {"value": 23.5}
    assert result[(1, 3)]["status"] == -70402
    assert "Unable to communicate" in result[(1, 3)]["description"]

    # The missing ones should get the global error
    assert result[(2, 4)]["status"] == -70407
    assert "Out of resources" in result[(2, 4)]["description"]
    assert result[(2, 5)]["status"] == -70407
    assert "Out of resources" in result[(2, 5)]["description"]


def test_format_characteristic_list_real_thermostat_scenario() -> None:
    """Test the exact scenario from the Resideo T9/T10 thermostat error."""
    # This is the exact response from the device when overwhelmed
    response = {"status": -70407}

    # These are the exact characteristics requested (103 total from the log)
    requested = {
        (7, 81),
        (4, 9),
        (2, 39),
        (5, 65),
        (5, 10),
        (2, 130),
        (5, 37),
        (3, 49),
        (6, 66),
        (7, 65),
        (7, 10),
        (4, 66),
        (2, 41),
        (3, 6),
        (5, 3),
        (7, 37),
        (6, 41),
        (2, 4),
        (6, 50),
        (4, 41),
        (6, 4),
        (7, 3),
        (4, 50),
        (5, 5),
        (3, 81),
        (7, 51),
        (1, 10),
        (6, 6),
        (7, 5),
        (2, 36),
        (3, 65),
        (3, 10),
        (5, 7),
        (1, 3),
        (3, 37),
        (7, 7),
        (2, 38),
        (3, 3),
        (5, 9),
        (1, 5),
        (6, 65),
        (7, 9),
        (3, 51),
        (2, 40),
        (3, 5),
        (4, 4),
        (5, 66),
        (2, 113),
        (6, 49),
        (1, 7),
        (2, 6),
        (7, 66),
        (5, 41),
        (5, 50),
        (2, 97),
        (3, 7),
        (5, 4),
        (4, 6),
        (7, 41),
        (6, 51),
        (7, 50),
        (1, 9),
        (7, 4),
        (1, 18),
        (2, 35),
        (2, 99),
        (6, 81),
        (3, 9),
        (5, 6),
        (4, 81),
        (2, 10),
        (2, 129),
        (6, 10),
        (2, 37),
        (3, 66),
        (4, 65),
        (4, 10),
        (6, 37),
        (1, 4),
        (2, 3),
        (3, 41),
        (6, 3),
        (3, 50),
        (4, 49),
        (3, 4),
        (4, 3),
        (2, 115),
        (1, 6),
        (2, 5),
        (6, 5),
        (5, 49),
        (4, 51),
        (4, 5),
        (7, 49),
        (2, 7),
        (6, 7),
        (7, 6),
        (5, 51),
        (4, 7),
        (5, 81),
        (2, 9),
        (4, 37),
        (6, 9),
    }

    result = format_characteristic_list(response, requested)

    assert len(result) == 103
    for char_id in requested:
        assert char_id in result
        assert result[char_id]["status"] == -70407
        assert result[char_id]["description"] == "Out of resources to process request."
