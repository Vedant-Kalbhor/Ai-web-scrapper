def generate_report(results):
    report_file = "vulnerability_report.txt"
    with open(report_file, "w", encoding="utf-8") as f:
        for item in results:
            f.write(item + "\n\n")
    return report_file
