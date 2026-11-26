require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const path = require('path');
const crypto = require('crypto'); // Node.js 內建加密模組

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const isCloud = Boolean(process.env.DB_HOST);
const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'test',
  ssl: isCloud ? { rejectUnauthorized: true } : undefined
});

// 密碼雜湊輔助函式（將明文轉為 64 字元 SHA-256 雜湊碼）
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// 1. 讀取所有留言（資安重點：明確指定欄位，絕不 SELECT password_hash 回傳給前端）
app.get('/api/messages', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, author, content, created_at FROM messages ORDER BY id DESC'
    );
    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 2. 新增留言（強制設定編輯/刪除密碼）
app.post('/api/messages', async (req, res) => {
  const { author, content, password } = req.body;
  if (!author || !content || !password) {
    return res.status(400).json({ success: false, message: '名字、內容與密碼皆不能為空' });
  }
  try {
    const pwdHash = hashPassword(password);
    await pool.query(
      'INSERT INTO messages (author, content, password_hash) VALUES (?, ?, ?)',
      [author, content, pwdHash]
    );
    res.json({ success: true, message: '留言新增成功' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 3. 修改留言（驗證密碼是否與資料庫吻合）
app.put('/api/messages/:id', async (req, res) => {
  const { content, password } = req.body;
  if (!content || !password) {
    return res.status(400).json({ success: false, message: '請輸入新內容與密碼' });
  }
  try {
    const pwdHash = hashPassword(password);
    const [result] = await pool.query(
      'UPDATE messages SET content = ? WHERE id = ? AND password_hash = ?',
      [content, req.params.id, pwdHash]
    );

    // affectedRows === 0 代表找不到該留言或密碼錯誤
    if (result.affectedRows === 0) {
      return res.status(403).json({ success: false, message: '密碼錯誤，無權修改此留言！' });
    }
    res.json({ success: true, message: '留言更新成功' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 4. 刪除留言（驗證密碼是否與資料庫吻合）
app.delete('/api/messages/:id', async (req, res) => {
  const { password } = req.body;
  if (!password) {
    return res.status(400).json({ success: false, message: '請輸入密碼以刪除留言' });
  }
  try {
    const pwdHash = hashPassword(password);
    const [result] = await pool.query(
      'DELETE FROM messages WHERE id = ? AND password_hash = ?',
      [req.params.id, pwdHash]
    );

    if (result.affectedRows === 0) {
      return res.status(403).json({ success: false, message: '密碼錯誤，無權刪除此留言！' });
    }
    res.json({ success: true, message: '已刪除留言' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`伺服器運行中：http://localhost:${PORT}`);
});
