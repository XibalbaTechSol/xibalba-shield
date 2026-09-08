import re

with open('ui/src/App.jsx', 'r') as f:
    content = f.read()

old_hero_start = '<section className="hero"><div className="hero-copy"><p className="eyebrow">'
new_hero_start = '<section className="hero"><div className="hero-copy"><img src="/shield-logo.png" alt="Shield Logo" className="hero-logo" /><p className="eyebrow">'
content = content.replace(old_hero_start, new_hero_start)

with open('ui/src/App.jsx', 'w') as f:
    f.write(content)
