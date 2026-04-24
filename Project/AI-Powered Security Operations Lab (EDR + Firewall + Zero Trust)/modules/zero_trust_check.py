def zero_trust(user, device_status):
    if device_status != "secure":
        return "Access Denied - Device not compliant"
    if user != "authorized":
        return "Access Denied - User not verified"
    return "Access Granted"
