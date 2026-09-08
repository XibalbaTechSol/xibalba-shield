with open('shield/backend/store.py', 'r') as f:
    content = f.read()

old_code = r'''        with self._conn:
            self._conn.execute("INSERT INTO password_reset_tokens(id,account_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)", (secrets.token_hex(16), row["account_id"], _hash_token(raw), (now + timedelta(minutes=ttl_minutes)).isoformat(), _now()))
        self.record_auth_event(event_type="password_reset_requested", email=normalized, tenant_id=row["tenant_id"])
        return raw'''

new_code = r'''        with self._conn:
            self._conn.execute("INSERT INTO password_reset_tokens(id,account_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)", (secrets.token_hex(16), row["account_id"], _hash_token(raw), (now + timedelta(minutes=ttl_minutes)).isoformat(), _now()))
        self.record_auth_event(event_type="password_reset_requested", email=normalized, tenant_id=row["tenant_id"])
        from .email_delivery import send_email
        reset_url = os.environ.get("SHIELD_PASSWORD_RESET_URL", "http://localhost").strip()
        separator = "&" if "?" in reset_url else "?"
        try:
            send_email(
                row["email"],
                "Reset your Xibalba Shield password",
                f"Use this time-limited link to reset your password:\n\n{reset_url}{separator}token={raw}\n",
            )
        except RuntimeError:
            pass
        return raw'''

content = content.replace(old_code, new_code)
with open('shield/backend/store.py', 'w') as f:
    f.write(content)
