# Web Security Best Practices

Here’s a comprehensive list of possible attacks you should prevent while developing a website, along with how JWT can be stolen and the corresponding prevention measures:

| **Attack Type**          | **How JWT Can Be Stolen**                                  | **Prevention** |
|-------------------------|----------------------------------------------------------|----------------|
| **XSS (Cross-Site Scripting)** | Token stored in `localStorage` can be stolen by injected scripts. | Use `httpOnly` and `Secure` cookies instead of `localStorage` or `sessionStorage`. |
| **MITM (Man-in-the-Middle Attack)** | Token sent over HTTP can be intercepted. | Use HTTPS (TLS/SSL) to encrypt data in transit. |
| **Refresh Token Theft** | If stolen, it can be used indefinitely. | Use **refresh token rotation** and revoke old tokens after use. Store refresh tokens in `httpOnly` cookies. |
| **Session Fixation** | If an attacker forces a victim to use a specific JWT, they can hijack their session. | Use **short-lived access tokens** and rotate refresh tokens. Revoke tokens on logout. |
| **CSRF (Cross-Site Request Forgery)** | If JWT is stored in cookies, an attacker can use them to make authenticated requests. | Use `SameSite=Strict` cookies and implement CSRF protection. |
| **Token Leakage via Logs** | JWTs logged in error messages or server logs can be stolen. | Avoid logging JWTs, especially in client-side code and server logs. |
| **Brute Force Attacks on JWT** | If the JWT secret is weak, attackers can guess it. | Use a **strong secret key** for signing JWTs and prefer **RS256 over HS256**. |
| **JWT Replay Attacks** | A stolen JWT can be reused until it expires. | Implement **JWT jti (unique ID) claims** and store used tokens in a denylist. |
| **Unauthorized Token Modification** | If using symmetric signing (HS256), an attacker who gets the secret can forge tokens. | Use asymmetric signing (RS256) so only the server can sign tokens. |
| **Scope Manipulation** | A user can modify JWT claims to escalate privileges. | **Validate JWT claims** on the backend and enforce proper authorization checks. |
| **Algorithm Confusion Attacks** | If a JWT is signed with an unexpected algorithm, an attacker might exploit it. | Specify the expected algorithm (`RS256`, `ES256`, etc.) in your JWT validation logic. |
| **Clickjacking** | A malicious site tricks users into interacting with a hidden iframe of your site. | Use `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none';`. |

Would you like a detailed breakdown of any specific attack? 🚀

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

