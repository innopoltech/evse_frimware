from typing import List


def validate_bytes_value_range(
    var_name: str, var_bytes: bytes, min_val: int, max_val: int
) -> bool:
    """
    Проверяет, что значение, представленное в виде массива байт, находится в допустимом диапазоне
    """
    int_value = int.from_bytes(var_bytes, byteorder="big", signed=True)
    if not min_val <= int_value <= max_val:
        raise ValueError(
            f"The value {int_value} is outside the allowed value "
            f"range [{min_val}..{max_val}] for {var_name}"
        )
    return True


def one_field_must_be_set(
    field_options: List[str], values: dict, mutually_exclusive: bool = False
) -> bool:
    """
    Проверяет, что хотя-бы одно из необходимых полей установленно
    """
    set_fields: List = []
    for field_name in field_options:
        field = values.get(f"{field_name}")
        if field is not None:
            set_fields.append(field)

    if mutually_exclusive and len(set_fields) != 1:
        raise ValueError(
            f"Exactly one field must be set but {len(set_fields)} "
            "are set instead. "
            f"\nSet fields: {set_fields}"
            f"\nField options: {field_options}"
        )

    if len(set_fields) == 0:
        raise ValueError(
            "At least one of these optional fields must be set "
            f"but {len(set_fields)} are set: {field_options}"
        )

    return True
