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
    'Dark Theme (#141414 bg, #1D1D1D card)': {
        'pairs': [
            ('Primary Body Text', '#ECECEC', '#1D1D1D', 4.5),
            ('Muted Text', '#A0A0A0', '#1D1D1D', 4.5),
            ('Benign Verdict Text', '#3FA66B', '#1D1D1D', 4.5),
            ('Review Verdict Text', '#D9A441', '#1D1D1D', 4.5),
            ('Malicious Verdict Text', '#E55B57', '#1D1D1D', 4.5),
            ('Focus Ring vs Card', '#E0A030', '#1D1D1D', 3.0),
            ('Focus Ring vs Page', '#E0A030', '#141414', 3.0),
            ('Button Text vs Button Bg', '#ECECEC', '#262626', 4.5),
        ]
    },
    'Light Theme (#F7F5F2 bg, #FFFFFF card)': {
        'pairs': [
            ('Primary Body Text', '#1B1B1A', '#FFFFFF', 4.5),
            ('Muted Text', '#6B6862', '#FFFFFF', 4.5),
            ('Benign Verdict Text', '#267A46', '#FFFFFF', 4.5),
            ('Review Verdict Text', '#8A6008', '#FFFFFF', 4.5),
            ('Malicious Verdict Text', '#B32D29', '#FFFFFF', 4.5),
            ('Focus Ring vs Card', '#1B1B1A', '#FFFFFF', 3.0),
            ('Focus Ring vs Page', '#1B1B1A', '#F7F5F2', 3.0),
            ('Button Text vs Button Bg', '#1B1B1A', '#EDE9E3', 4.5),
        ]
    }
}

for t_name, t_data in themes.items():
    print('=' * 80)
    print(t_name)
    print('=' * 80)
    print(f"{'Element / Role':<32} {'Color 1':<10} {'Color 2':<10} {'Ratio':<10} {'Req':<8} {'Status'}")
    print('-' * 80)
    for role, c1, c2, target in t_data['pairs']:
        cr = contrast(c1, c2)
        passed = 'PASS (>= req)' if cr >= target else 'FAIL'
        print(f"{role:<32} {c1:<10} {c2:<10} {cr:.2f}:1    {target:.1f}:1    {passed}")
    print()
