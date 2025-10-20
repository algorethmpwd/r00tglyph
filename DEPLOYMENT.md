# R00tGlyph Deployment Guide

## 🚀 Deploy to Render.com (Recommended - FREE!)

### Why Render?
- ✅ **FREE tier** with PostgreSQL database
- ✅ **Automatic HTTPS** included
- ✅ **Auto-deploy** from GitHub pushes
- ✅ **No credit card** required for free tier
- ✅ **Perfect for Flask apps**

---

## Quick Deploy (5 Minutes)

### Step 1: Push to GitHub
```bash
cd /home/algorethm/Documents/code/R00tGlyph

# Initialize git if not already done
git add .
git commit -m "Prepare for Render deployment"
git push origin main
```

### Step 2: Deploy on Render

1. **Go to**: https://render.com
2. **Sign up/Login** with GitHub
3. **Click** "New +" → "Blueprint"
4. **Connect** your R00tGlyph repository
5. **Click** "Apply" - Render will:
   - Read `render.yaml`
   - Create web service
   - Create PostgreSQL database
   - Deploy automatically!

### Step 3: Done!
Your app will be live at: `https://r00tglyph.onrender.com`

---

## Alternative: Deploy to Railway.app (Also FREE!)

### Why Railway?
- ✅ Free $5/month credit
- ✅ Easy PostgreSQL setup
- ✅ Great developer experience

### Quick Deploy:

1. **Install Railway CLI:**
   ```bash
   npm install -g @railway/cli
   ```

2. **Login and Deploy:**
   ```bash
   cd /home/algorethm/Documents/code/R00tGlyph
   railway login
   railway init
   railway add --database postgres
   railway up
   ```

3. **Done!** Railway gives you a URL.

---

## Alternative: PythonAnywhere (FREE - 512MB)

### Why PythonAnywhere?
- ✅ Completely free tier
- ✅ Made for Python/Flask apps
- ✅ Web-based file editor
- ✅ No credit card needed

### Steps:

1. Go to: https://www.pythonanywhere.com
2. Sign up for FREE account
3. Upload your code via:
   - Git clone from your repo
   - Or upload files manually
4. Configure WSGI file
5. Reload web app

**Tutorial**: https://help.pythonanywhere.com/pages/Flask/

---

## Alternative: Heroku (Requires Credit Card)

Heroku is great but:
- ❌ No longer has a completely free tier
- ❌ Requires credit card even for free dynos
- ✅ Still good for production

If you want to use Heroku:

```bash
# Create Procfile (already done)
# Add requirements (already done)

# Deploy
heroku login
heroku create r00tglyph
git push heroku main
heroku addons:create heroku-postgresql:mini
```

---

## Alternative: DigitalOcean App Platform

- ✅ $5/month (not free)
- ✅ Great performance
- ✅ Easy scaling

```bash
# Install doctl CLI
doctl apps create --spec .do/app.yaml
```

---

## ⚠️ Why NOT Vercel/Netlify?

**DON'T use these for R00tGlyph:**
- ❌ **Vercel**: Serverless only, no persistent SQLite
- ❌ **Netlify**: Static sites only
- ❌ Both don't support Flask well

---

## 🎯 RECOMMENDED CHOICE: Render.com

**Best for R00tGlyph because:**
1. Completely free
2. PostgreSQL included
3. Perfect Flask support
4. Auto-deploy from GitHub
5. HTTPS automatic
6. No credit card needed

---

## Database Migration (SQLite → PostgreSQL)

Your app uses SQLite locally but PostgreSQL in production.

**Already handled!** The app will:
1. Detect PostgreSQL via `DATABASE_URL` env var
2. Auto-create all tables on first run
3. Run `update_db.py` to populate challenges

**Manual migration if needed:**
```bash
# Export from SQLite
sqlite3 instance/r00tglyph.db .dump > backup.sql

# Import to PostgreSQL (on Render shell)
psql $DATABASE_URL < backup.sql
```

---

## Environment Variables on Render

Automatically set by `render.yaml`:
- ✅ `DATABASE_URL` - PostgreSQL connection
- ✅ `SECRET_KEY` - Auto-generated secure key
- ✅ `FLASK_ENV=production`

---

## After Deployment

### 1. Initialize Database
SSH into Render shell or add this to startup:
```bash
python3 update_db.py
```

### 2. Test Your App
```bash
curl https://r00tglyph.onrender.com
```

### 3. Monitor
- Render dashboard shows logs
- Free tier sleeps after 15min inactivity
- First request takes ~30sec to wake up

---

## Performance Tips

### Free Tier Limitations:
- Sleeps after 15min inactivity
- 512MB RAM
- Shared CPU

### Upgrade to Paid ($7/month):
- No sleep
- More resources
- Faster performance

---

## Custom Domain (Optional)

On Render free tier:
1. Go to Settings
2. Add custom domain
3. Update DNS records
4. Done!

---

## Troubleshooting

### App won't start?
Check Render logs:
```bash
# In Render dashboard
Logs → View logs
```

### Database errors?
```bash
# Check if DATABASE_URL is set
echo $DATABASE_URL
```

### Port issues?
App reads `PORT` env var (Render sets automatically)

---

## Summary

**Easiest deployment:** Render.com
**Best free option:** Render.com or PythonAnywhere
**Best performance:** DigitalOcean ($5/month)
**DON'T use:** Vercel, Netlify

**Recommended: Just use Render! 🚀**

Follow this:
1. Push code to GitHub
2. Connect to Render
3. Deploy via Blueprint
4. Done in 5 minutes!
