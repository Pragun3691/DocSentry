def rel_lum(hex_color):
    hex_color = hex_color.lstrip('#')
    if len(hex_color) == 3:
        hex_color = ''.join(c*2 for c in hex_color)
    rgb = [int(hex_color[i:i+2], 16) / 255.0 for i in (0, 2, 4)]
    rgb = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2]

def contrast(c1, c2):
    l1 = rel_lum(c1)
    l2 = rel_lum(c2)
    return (max(l1, l2) + 0.05) / (min(l1, l2) + 0.05)

themes = {
    'Light Theme (Paper #F1EFE6, Card #FBFAF5, Inset #E8E5DA, Border #7B7668)': {
        'pairs': [
            # Text >= 4.5:1
            ('Ink on Paper (Text)', '#141412', '#F1EFE6', 4.5),
            ('Ink on Card (Text)', '#141412', '#FBFAF5', 4.5),
            ('Ink on Inset (Text)', '#141412', '#E8E5DA', 4.5),
            ('Ink on Mint / Peach (Text)', '#141412', '#D4F3C9', 4.5),
            ('Muted Ink on Inset (Text)', '#5F5C52', '#E8E5DA', 4.5),
            ('Benign Verdict on Tint (Text)', '#1F7A45', '#E6F5EC', 4.5),
            ('Review Verdict on Tint (Text)', '#8A5600', '#FDF4E3', 4.5),
            ('Malicious Verdict on Tint (Text)', '#C0392B', '#FCECEB', 4.5),
            # UI Components >= 3.0:1
            ('Focus Ring Ink on Paper (UI)', '#141412', '#F1EFE6', 3.0),
            ('Border #7B7668 on Card #FBFAF5 (UI)', '#7B7668', '#FBFAF5', 3.0),
            ('Border #7B7668 on Inset #E8E5DA (UI)', '#7B7668', '#E8E5DA', 3.0),
            ('Gauge Zone Divider Ink on Tint (UI)', '#141412', '#E6F5EC', 3.0),
            ('Chart Bar Benign on Inset (UI)', '#1F7A45', '#E8E5DA', 3.0),
            ('Chart Bar Malicious on Inset (UI)', '#C0392B', '#E8E5DA', 3.0),
        ]
    },
    'Dark Theme (Ground #10100E, Card #1C1C19, Inset #272723, Border #737167)': {
        'pairs': [
            # Text >= 4.5:1
            ('Ink on Ground (Text)', '#F1EFE6', '#10100E', 4.5),
            ('Ink on Card (Text)', '#F1EFE6', '#1C1C19', 4.5),
            ('Ink on Inset (Text)', '#F1EFE6', '#272723', 4.5),
            ('Muted Ink on Inset (Text)', '#A8A498', '#272723', 4.5),
            ('Benign Verdict on Tint (Text)', '#49B675', '#193222', 4.5),
            ('Review Verdict on Tint (Text)', '#E0A030', '#332712', 4.5),
            ('Malicious Verdict on Tint (Text)', '#E8685C', '#381D1A', 4.5),
            # UI Components >= 3.0:1
            ('Focus Ring Ink on Ground (UI)', '#F1EFE6', '#10100E', 3.0),
            ('Border #737167 on Card #1C1C19 (UI)', '#737167', '#1C1C19', 3.0),
            ('Border #737167 on Inset #272723 (UI)', '#737167', '#272723', 3.0),
            ('Gauge Zone Divider Ink on Tint (UI)', '#F1EFE6', '#193222', 3.0),
            ('Chart Bar Benign on Inset (UI)', '#49B675', '#272723', 3.0),
            ('Chart Bar Malicious on Inset (UI)', '#E8685C', '#272723', 3.0),
        ]
    }
}

all_ok = True
for t_name, t_data in themes.items():
    print('=' * 90)
    print(t_name)
    print('=' * 90)
    print(f"{'Element / Role':<40} {'Color 1':<10} {'Color 2':<10} {'Ratio':<10} {'Req':<8} {'Status'}")
    print('-' * 90)
    for role, c1, c2, target in t_data['pairs']:
        cr = contrast(c1, c2)
        passed = cr >= target
        if not passed:
            all_ok = False
        status = 'PASS' if passed else 'FAIL'
        print(f"{role:<40} {c1:<10} {c2:<10} {cr:.2f}:1    {target:.1f}:1    {status}")
    print()

assert all_ok, 'Contrast check failed!'
print('ALL CONTRAST CHECKS PASSED!')
