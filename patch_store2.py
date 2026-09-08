with open('shield/backend/store.py', 'r') as f:
    lines = f.readlines()

new_lines = []
skip = 0
for line in lines:
    if 'except Exception as exc:' in line:
        new_lines.append('        except Exception:\n            pass\n')
        skip = 3
    elif skip > 0:
        skip -= 1
        continue
    else:
        new_lines.append(line)

with open('shield/backend/store.py', 'w') as f:
    f.writelines(new_lines)
