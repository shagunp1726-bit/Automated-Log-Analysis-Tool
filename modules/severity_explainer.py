def determine_severity(score):
    if score >= 10:
        return "High"
    elif score >= 5:
        return "Medium"
    return "Low"
