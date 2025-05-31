rule MA_20250531_1486
{
    meta:
        description = "Malware detected by ICTI-ADS"
        origin = "Syria"
        target_sector = "General Purpose"
        risk_score = 7
        
    strings:
        $hash = "69c88e9e2567193512bd9fcc71b3fa2319547dc302b557bf03ba28db84d28006"
        
    condition:
        $hash or filesize < 10MB
}