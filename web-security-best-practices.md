# Web Security Best Practices

## 1. **Store JWTs in HttpOnly & Secure Cookies**
### Why?
- Prevents JavaScript from accessing the token, blocking XSS attacks.
- Ensures cookies are only sent over HTTPS.
- Protects against CSRF attacks when configured correctly.

### Implementation (Backend - Express/NestJS)
```typescript
import cookie from 'cookie';

app.post('/login', (req, res) => {
    const token = generateJWT(req.user);  // Generate JWT
    res.setHeader('Set-Cookie', cookie.serialize('jwt', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict',
        maxAge: 60 * 60 * 24, // 1 day
        path: '/'
    }));
    res.json({ message: "Login successful" });
});
```

### Frontend Requests (Angular/NestJS)
```typescript
this.http.post('/login', credentials, { withCredentials: true }).subscribe(response => {
    console.log("Logged in!");
});
```

---

## 2. **Use a Strong Content Security Policy (CSP)**
### Why?
- Blocks unauthorized inline scripts and third-party malicious scripts.

### Implementation (Backend - Express/NestJS)
```typescript
app.use((req, res, next) => {
    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"
    );
    next();
});
```

### CSP via HTML Meta Tag
```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'">
```

---

## 3. **Sanitize All User Inputs to Prevent XSS**
### Why?
- Prevents attackers from injecting malicious scripts into forms or URLs.

### Implementation (Backend - Express/NestJS)
```typescript
import { body, validationResult } from 'express-validator';

app.post('/comment',
    body('text').escape(),  // Escapes harmful characters
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        saveComment(req.body.text);
        res.json({ message: "Comment added" });
    }
);
```

---

## 4. **Enable a Web Application Firewall (WAF)**
### Why?
- Detects and blocks malicious requests, including XSS, SQL injection, and brute-force attacks.

### Options:
- **AWS WAF** (for AWS-hosted applications)
- **Cloudflare WAF** (for websites & APIs)
- **ModSecurity** (Open-source WAF for Nginx/Apache)

#### Installing ModSecurity for Nginx
```bash
sudo apt install libapache2-mod-security2
```

---

## 5. **Use Short-Lived JWTs & Refresh Token Rotation**
### Why?
- Short-lived tokens expire quickly, reducing the risk of stolen tokens being useful.
- Refresh token rotation ensures old tokens can’t be reused if stolen.

### Implementation (Backend - Express/NestJS)
```typescript
const accessToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '15m' });
const refreshToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
```

### Store Refresh Tokens in HttpOnly Cookies
```typescript
res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Strict",
    path: "/refresh"
});
```

### Rotate Refresh Tokens on Each Use
```typescript
app.post('/refresh', (req, res) => {
    const oldRefreshToken = req.cookies.refreshToken;
    jwt.verify(oldRefreshToken, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);

        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);

        // Revoke the old token
        revokeToken(oldRefreshToken);

        res.cookie("refreshToken", newRefreshToken, { httpOnly: true, secure: true });
        res.json({ accessToken: newAccessToken });
    });
});
```

---

## 6. **Logout Mechanism - Clearing Cookies**
```typescript
res.clearCookie("jwt", { path: "/" });
res.clearCookie("refreshToken", { path: "/" });
res.json({ message: "Logged out" });
```

---

## 🔥 **Final Security Checklist**
✅ **JWT stored in `httpOnly` & `Secure` cookies**  
✅ **Strong CSP to prevent inline scripts**  
✅ **Sanitize all user input to prevent XSS**  
✅ **Enable WAF (Cloudflare, AWS, or ModSecurity)**  
✅ **Use short-lived JWTs with refresh token rotation**  
✅ **CSRF protection enabled (`SameSite=Strict` or CSRF tokens)**  
✅ **CORS configured to allow only trusted origins**  

---

## 🚀 **Next Steps**
If migrating from `localStorage`-based authentication, **switch to httpOnly cookies immediately!** This guide provides a secure foundation for web application security.

