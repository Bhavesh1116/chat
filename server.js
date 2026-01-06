// ✅ UPDATED SERVER WITH VOICE CALLING + GROUP CHAT + SETTINGS FEATURE
import express from "express";
import cors from "cors";
import { Server } from "socket.io";
import { createServer } from "http";
import path from "path";
import { fileURLToPath } from "url";
import bodyParser from "body-parser";
import { MongoClient } from "mongodb";
import fetch from "node-fetch";
import dotenv from "dotenv";
dotenv.config();

// 📁 Path setup tum
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ⚙️ Express + HTTP + Socket.io
const app = express();

// ✅ YEH EK LINE ADD KARO:
app.set('trust proxy', 1);

const server = createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
});

// 🔧 Middleware
app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

import rateLimit from 'express-rate-limit';
import AbortController from 'abort-controller';

// ✅ 1. Rate Limiter define karo
const smallLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // maximum 100 requests per minute
  message: 'Too many requests, please try again later.',
  standardHeaders: true,
  legacyHeaders: false
});

// ✅ 2. Origin Validation function (Tumhare exact URL ke saath)
function validateOrigin(req) {
  const origin = req.get('origin');
  if (!origin) return true;
  
  const ALLOWED_ORIGINS = [
    'http://localhost:3000',
    'http://localhost:4000',
    'https://real-time-chat-86r5.onrender.com' // ← TUMHARA EXACT URL
  ];
  
  return ALLOWED_ORIGINS.includes(origin);
}

// ✅ 3. Safe Fetch with timeout
async function safeFetch(url, options = {}, timeoutMs = 7000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(id);
  }
}

// 🗃️ MongoDB Setup - ✅ SETTINGS COLLECTION ADD KAR DIYA
const uri = process.env.MONGO_URI;
const client = new MongoClient(uri, {
  ssl: true,
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const dbName = "ChatDB";
let userCollection, historyCollection, requestCollection, friendCollection, 
    privateMsgCollection, groupCollection, groupMessageCollection, settingsCollection; // ✅ SETTINGS ADDED

client
  .connect()
  .then(() => {
    const db = client.db(dbName);
    userCollection = db.collection("user");
    historyCollection = db.collection("bot_history");
    requestCollection = db.collection("friend_requests");
    friendCollection = db.collection("friends");
    privateMsgCollection = db.collection("privateMessages");
    groupCollection = db.collection("groups");
    groupMessageCollection = db.collection("groupMessages");
    settingsCollection = db.collection("user_settings"); // ✅ NEW SETTINGS COLLECTION
    console.log("✅ MongoDB Connected");
  })
  .catch((err) => console.error("❌ Mongo Connection Error:", err));

// 🔐 UID generator
function generateUID() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// 🧠 Bot active state
let botActive = false;

// 🤖 Gemini Bot Reply (Short Hinglish)
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
async function generateBotReply(prompt) {
  try {
    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${GEMINI_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: `Reply in short Hinglish. ${prompt}` }] }],
        }),
      }
    );
    const data = await res.json();
    return data.candidates?.[0]?.content?.parts?.[0]?.text || "Bot confused hai.";
  } catch (e) {
    console.error("❌ Bot error:", e);
    return "Bot reply failed.";
  }
}

// 🌐 Routes
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// 📝 Register User
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).send("Fill all fields");

    const exist = await userCollection.findOne({ $or: [{ email }, { name }] });
    if (exist) return res.status(400).send("User already exists");

    const uid = generateUID();
    await userCollection.insertOne({ name, email, password, uid });
    res.send("Registration success");
  } catch (e) {
    console.error("❌ Register Error:", e);
    res.status(500).send("Server error");
  }
});

// 🔑 Login
app.post("/login", async (req, res) => {
  try {
    let email, password;
    if (req.headers["content-type"]?.includes("application/json")) {
      ({ email, password } = req.body);
    } else {
      email = req.body.email;
      password = req.body.password;
    }

    const user = await userCollection.findOne({ email, password });
    if (!user) return res.status(401).send("Invalid");

    res.json({ name: user.name, email: user.email, uid: user.uid });
  } catch (e) {
    console.error("❌ Login Error:", e);
    res.status(500).send("Server error");
  }
});

// ❌ Delete Account - ✅ UPDATED FOR SETTINGS
app.post("/delete-account", async (req, res) => {
  try {
    const { userId } = req.body; // ✅ Changed from email to userId
    if (!userId) return res.status(400).send("Missing user ID");

    // ✅ DELETE FROM ALL COLLECTIONS INCLUDING SETTINGS
    await userCollection.deleteOne({ uid: userId });
    await friendCollection.deleteMany({ 
      $or: [{ uid1: userId }, { uid2: userId }] 
    });
    await requestCollection.deleteMany({ 
      $or: [{ from: userId }, { to: userId }] 
    });
    await privateMsgCollection.deleteMany({ 
      $or: [{ room: { $regex: userId } }] 
    });
    await settingsCollection.deleteOne({ userId }); // ✅ DELETE SETTINGS
    
    res.send("Account deleted successfully");
  } catch (e) {
    console.error("❌ Delete Account Error:", e);
    res.status(500).send("Server error");
  }
});

// 📜 Bot History
app.get("/bot-history", async (req, res) => {
  try {
    const name = req.query.name;
    const rows = await historyCollection.find({ name }).toArray();
    res.json(rows);
  } catch (e) {
    console.error("❌ History Fetch Error:", e);
    res.status(500).send("Error fetching history");
  }
});

// 👥 Get Users
app.get("/get-users", async (req, res) => {
  try {
    const users = await userCollection.find().toArray();
    res.json(users);
  } catch (e) {
    console.error("❌ Get Users Error:", e);
    res.status(500).send("Server error");
  }
});

// 📨 Friend Request System
app.post("/send-request", async (req, res) => {
  const { fromUid, toUid } = req.body;
  const toUser = await userCollection.findOne({ uid: toUid });
  if (!toUser) return res.status(404).send("UID not found");

  const alreadySent = await requestCollection.findOne({ from: fromUid, to: toUid });
  if (alreadySent) return res.status(400).send("Request already sent");

  await requestCollection.insertOne({ from: fromUid, to: toUid });
  res.send("Request sent");
});

app.get("/get-requests", async (req, res) => {
  const uid = req.query.uid;
  const requests = await requestCollection.find({ to: uid }).toArray();
  const names = await Promise.all(
    requests.map(async (r) => {
      const u = await userCollection.findOne({ uid: r.from });
      return u?.name || r.from;
    })
  );
  res.json(names);
});

app.post("/accept-request", async (req, res) => {
  const { fromUid, toUid } = req.body;
  await friendCollection.insertMany([
    { uid1: fromUid, uid2: toUid },
    { uid1: toUid, uid2: fromUid },
  ]);
  await requestCollection.deleteOne({ from: fromUid, to: toUid });
  res.send("Friend added");
});

app.get("/get-friends", async (req, res) => {
  try {
    const uid = req.query.uid;
    const friends = await friendCollection.find({ uid1: uid }).toArray();
    const result = await Promise.all(
      friends.map(async (f) => {
        const u = await userCollection.findOne({ uid: f.uid2 });
        return {
          name: u?.name || f.uid2,
          uid: u?.uid || f.uid2,
          online: Object.values(users).some((x) => x?.uid === (u?.uid || f.uid2)),
        };
      })
    );
    res.json(result);
  } catch (e) {
    console.error("❌ Get Friends Error:", e);
    res.status(500).send("Server error");
  }
});

app.post("/delete-friend", async (req, res) => {
  try {
    const { uid1, uid2 } = req.body;
    await friendCollection.deleteMany({
      $or: [
        { uid1, uid2 },
        { uid1: uid2, uid2: uid1 }
      ]
    });
    res.send("Friend removed successfully");
  } catch (e) {
    res.status(500).send("Error removing friend");
  }
});

// ✅ GET Saved Private Chat
app.get("/get-room-messages", async (req, res) => {
  try {
    const { room } = req.query;
    if (!room) return res.status(400).send("Missing room");
    const messages = await privateMsgCollection.find({ room }).sort({ timestamp: 1 }).toArray();
    res.json(messages);
  } catch (e) {
    console.error("❌ Message Fetch Error:", e);
    res.status(500).send("Error loading messages");
  }
});

// ❌ Clear Room Messages
app.post("/clear-room", async (req, res) => {
  try {
    const { room } = req.body;
    if (!room) return res.status(400).send("Missing room");
    await privateMsgCollection.deleteMany({ room });
    res.send("Room cleared");
  } catch (e) {
    console.error("❌ Clear Room Error:", e);
    res.status(500).send("Error clearing room");
  }
});

// ✅ Phishing Check
app.post('/check-phishing', express.json(), async (req, res) => {
  try {
    const { text } = req.body;
    if (!text) return res.json({ isPhishing: false, confidence: 0 });

    console.log('🔍 Checking phishing for:', text);

    // ✅ 1. Pehle Hugging Face API try karo
    try {
      const response = await fetch("https://phishing-2dld.onrender.com/check", {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
        timeout: 5000
      });

      if (response.ok) {
        const result = await response.json();
        console.log('🤖 Hugging Face Result:', result);
        
        if (result.prediction === "PHISHING") {
          return res.json({ isPhishing: true, confidence: result.confidence || 0.8 });
        }
      }
    } catch (hfError) {
      console.log('❌ Hugging Face failed, using fallback');
    }

    // ✅ 2. IMPROVED HEURISTIC CHECK
    const phishingKeywords = [
      'login', 'verify', 'secure', 'account', 'update', 'confirm', 
      'bank', 'paypal', 'password', 'credit', 'urgent', 'immediately',
      'facebook', 'instagram', 'whatsapp', 'amazon', 'paytm', 'sbi', 'hdfc',
      'lottery', 'prize', 'won', 'winner', 'reward', 'claim', 'free', 'money',
      'security', 'alert', 'warning', 'suspicious', 'activity', 'verification',
      'hack', 'crack', 'password', 'recovery', 'unlock', 'suspend', 'limit',
      'phishing', 'scam', 'fraud', 'cheat', 'trick', 'steal', 'hack'
    ];
    
    const urlRegex = /https?:\/\/[^\s]+/g;
    const urls = text.match(urlRegex) || [];
    const hasUrls = urls.length > 0;
    
    const lowerText = text.toLowerCase();
    const hasSuspiciousKeywords = phishingKeywords.some(keyword => 
      lowerText.includes(keyword.toLowerCase())
    );
    
    const suspiciousPatterns = [
      /lottery.*won|won.*lottery/i,
      /prize.*claim|claim.*prize/i,
      /bank.*verif|verif.*bank/i,
      /password.*reset|reset.*password/i,
      /security.*alert|alert.*security/i,
      /urgent.*action|action.*urgent/i
    ];
    
    const hasSuspiciousPattern = suspiciousPatterns.some(pattern => 
      pattern.test(text)
    );

    const isPhishing = hasUrls && (hasSuspiciousKeywords || hasSuspiciousPattern);
    const confidence = isPhishing ? 0.85 : 0.1;

    console.log('🔍 Heuristic Check:', {
      hasUrls,
      hasSuspiciousKeywords,
      hasSuspiciousPattern, 
      isPhishing,
      confidence
    });

    return res.json({ isPhishing, confidence });

  } catch (err) {
    console.error('❌ Phishing check error:', err);
    return res.json({ isPhishing: false, confidence: 0 });
  }
});

// ✅ Toxicity Check
app.post('/check-toxicity', smallLimiter, express.json({ limit: '12kb' }), async (req, res) => {
  try {
    if (!validateOrigin(req)) return res.status(403).json({ error: 'Forbidden origin' });

    const { message } = req.body;
    if (!message || typeof message !== 'string') {
      return res.status(400).json({ isToxic: false, score: 0, error: 'Invalid message' });
    }

    const PERSPECTIVE_API_KEY = process.env.PERSPECTIVE_API_KEY;

    if (PERSPECTIVE_API_KEY) {
      const payload = {
        comment: { text: message },
        languages: ['en', 'hi'],
        requestedAttributes: { 
          TOXICITY: {}, 
          SEVERE_TOXICITY: {}, 
          IDENTITY_ATTACK: {}, 
          THREAT: {}, 
          INSULT: {}, 
          PROFANITY: {} 
        }
      };

      const url = `https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze?key=${PERSPECTIVE_API_KEY}`;
      const apiRes = await safeFetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }, 7000);

      if (apiRes && apiRes.ok) {
        const json = await apiRes.json().catch(() => ({}));
        const attrs = json.attributeScores || {};
        let maxScore = 0;
        
        for (const key of Object.keys(attrs)) {
          const v = attrs[key]?.summaryScore?.value || 0;
          if (v > maxScore) maxScore = v;
        }

        const hindiBadWords = ['madarchod','bhenchod','chutiya','lund','gaand','kutta','kamina','harami'];
        const containsHindi = hindiBadWords.some(w => message.toLowerCase().includes(w));
        const finalToxic = maxScore > 0.7 || containsHindi;
        
        return res.json({ 
          isToxic: finalToxic, 
          score: Number(maxScore.toFixed(3)),
          detected: containsHindi ? 'HINDI_BAD_WORD' : 'PERSPECTIVE_API'
        });
      }
    }

    const badWords = [
      'fuck','shit','bitch','asshole','dick','pussy','bastard','whore',
      'madarchod','bhenchod','chutiya','lund','gaand','maa ki','behen ki','kutta','kamina','harami'
    ];
    
    const lower = message.toLowerCase();
    const found = badWords.find(w => lower.includes(w));
    const isToxic = !!found;
    
    return res.json({ 
      isToxic, 
      score: isToxic ? 0.85 : 0.05,
      detected: found || 'CLEAN'
    });

  } catch (err) {
    console.error('❌ /check-toxicity error:', err);
    const badWords = ['madarchod','bhenchod','chutiya','lund','gaand'];
    const lower = (message || '').toLowerCase();
    const isToxic = badWords.some(w => lower.includes(w));
    return res.json({ isToxic, score: isToxic ? 0.8 : 0.1, detected: 'FALLBACK' });
  }
});

// 📋 Create Group
app.post("/create-group", async (req, res) => {
  try {
    const { name, createdBy, participants } = req.body;
    
    if (!name || !createdBy) {
      return res.status(400).send("Group name and creator are required");
    }

    const groupId = generateUID();
    const groupData = {
      groupId,
      name,
      createdBy,
      participants: participants || [createdBy],
      createdAt: new Date()
    };

    await groupCollection.insertOne(groupData);
    res.json({ message: "Group created successfully", groupId });
  } catch (e) {
    console.error("❌ Create Group Error:", e);
    res.status(500).send("Server error");
  }
});

// 👥 Add Participants to Group
app.post("/add-to-group", async (req, res) => {
  try {
    const { groupId, userId } = req.body;
    
    if (!groupId || !userId) {
      return res.status(400).send("Group ID and User ID are required");
    }

    await groupCollection.updateOne(
      { groupId },
      { $addToSet: { participants: userId } }
    );
    
    res.send("User added to group");
  } catch (e) {
    console.error("❌ Add to Group Error:", e);
    res.status(500).send("Server error");
  }
});

// 📜 Get User Groups
app.get("/get-user-groups", async (req, res) => {
  try {
    const userId = req.query.userId;
    const groups = await groupCollection.find({ 
      participants: userId 
    }).toArray();
    
    res.json(groups);
  } catch (e) {
    console.error("❌ Get User Groups Error:", e);
    res.status(500).send("Server error");
  }
});

// 💬 Get Group Messages
app.get("/get-group-messages", async (req, res) => {
  try {
    const { groupId } = req.query;
    const messages = await groupMessageCollection.find({ 
      groupId 
    }).sort({ timestamp: 1 }).toArray();
    
    res.json(messages);
  } catch (e) {
    console.error("❌ Get Group Messages Error:", e);
    res.status(500).send("Error loading group messages");
  }
});

// 🧹 Clear Group Messages
app.post("/clear-group-messages", async (req, res) => {
  try {
    const { groupId } = req.body;
    await groupMessageCollection.deleteMany({ groupId });
    res.send("Group messages cleared");
  } catch (e) {
    console.error("❌ Clear Group Messages Error:", e);
    res.status(500).send("Error clearing group messages");
  }
});

// ✅ CLEAR GROUP CHAT ROUTE
app.post("/clear-group-chat", async (req, res) => {
  try {
    const { groupId } = req.body;
    await groupMessageCollection.deleteMany({ groupId });
    
    io.to(`group-${groupId}`).emit("chat-cleared", {
      groupId,
      clearedBy: req.body.clearedBy || "Someone"
    });
    
    res.send("Chat cleared successfully");
  } catch (e) {
    console.error("❌ Clear Group Chat Error:", e);
    res.status(500).send("Error clearing chat");
  }
});

// ✅ RENAME GROUP ROUTE
app.post("/rename-group", async (req, res) => {
  try {
    const { groupId, newName } = req.body;
    
    if (!groupId || !newName) {
      return res.status(400).send("Group ID and new name are required");
    }

    await groupCollection.updateOne(
      { groupId },
      { $set: { name: newName } }
    );
    
    io.to(`group-${groupId}`).emit("group-renamed", {
      groupId,
      newName
    });
    
    res.send("Group renamed successfully");
  } catch (e) {
    console.error("❌ Rename Group Error:", e);
    res.status(500).send("Error renaming group");
  }
});

// ✅ NEW SETTINGS ROUTES - YAHAN ADD KARO
// ✅ NEW SETTINGS ROUTES - YAHAN ADD KARO
app.get("/get-settings", async (req, res) => {
  try {
    const userId = req.query.userId;
    if (!userId) return res.status(400).json({ error: "User ID required" });

    const settingsDoc = await settingsCollection.findOne({ userId });
    res.json(settingsDoc?.settings || {});
  } catch (e) {
    console.error("❌ Get Settings Error:", e);
    res.status(500).json({ error: "Error loading settings" });
  }
});

app.post("/save-settings", async (req, res) => {
  try {
    const { userId, settings } = req.body;
    if (!userId || !settings) return res.status(400).json({ error: "Invalid data" });

    await settingsCollection.updateOne(
      { userId },
      { $set: { userId, settings, updatedAt: new Date() } },
      { upsert: true }
    );
    
    res.json({ message: "Settings saved successfully" });
  } catch (e) {
    console.error("❌ Save Settings Error:", e);
    res.status(500).json({ error: "Error saving settings" });
  }
});

app.post("/logout", async (req, res) => {
  try {
    res.json({ message: "Logged out successfully" });
  } catch (e) {
    res.status(500).json({ error: "Error during logout" });
  }
});

// ✅ Server mein ye route add karo
app.get("/get-gemini-key", (req, res) => {
  res.json({ apiKey: process.env.GEMINI_API_KEY });
});
// 🧠 Socket.IO Logic
const users = {};       // socketId -> { uid, name, socketId }
const activeCalls = {}; // uid -> call state

io.on("connection", (socket) => {
  console.log("🔌 User connected:", socket.id);

  // Register user with name/uid
  socket.on("register-call-user", (data) => {
    if (data && data.uid) {
      users[socket.id] = {
        uid: data.uid,
        name: data.name || "Unknown",
        socketId: socket.id
      };
      console.log("📞 Registered:", data.uid, "->", socket.id);
    }
  });

  socket.on("private-message", async (data) => {
    try {
      // ✅ Phishing check
      const phishingResponse = await fetch('/check-phishing', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: data.text })
      });
      
      const phishingResult = await phishingResponse.json();
      
      if (phishingResult.isPhishing) {
        io.to(data.room).emit("private-message", {
          room: data.room,
          sender: "System",
          text: `🚫 Phishing link detected from ${data.sender}`
        });
        return;
      }

      // ✅ Toxicity check
      const toxicityResponse = await fetch('/check-toxicity', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: data.text })
      });
      
      const toxicityResult = await toxicityResponse.json();
      
      if (toxicityResult.isToxic) {
        io.to(data.room).emit("private-message", {
          room: data.room,
          sender: "System", 
          text: `🚫 Message from ${data.sender} was blocked for toxic behavior`
        });
        return;
      }

      // ✅ Safe message forward
      socket.to(data.room).emit("private-message", data);
      await privateMsgCollection.insertOne({
        room: data.room,
        sender: data.sender,
        text: data.text,
        timestamp: new Date()
      });

    } catch (error) {
      console.error("❌ Message error:", error);
    }
  });

  // ✅ Group message with safety checks
  socket.on("group-message", async (data) => {
    try {
      console.log('🔍 Checking group message:', data.text);
      
      // ✅ Phishing check
      const phishingResponse = await fetch(`http://localhost:${process.env.PORT || 3000}/check-phishing`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: data.text })
      });
      
      const phishingResult = await phishingResponse.json();
      
      if (phishingResult.isPhishing) {
        io.to(`group-${data.groupId}`).emit("group-message", {
          groupId: data.groupId,
          sender: "System",
          senderName: "System",
          text: `🚫 Phishing link detected from ${data.senderName}. Message blocked.`,
          timestamp: new Date()
        });
        return;
      }

      // ✅ Toxicity check
      const toxicityResponse = await fetch(`http://localhost:${process.env.PORT || 3000}/check-toxicity`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: data.text })
      });
      
      const toxicityResult = await toxicityResponse.json();
      
      if (toxicityResult.isToxic) {
        io.to(`group-${data.groupId}`).emit("group-message", {
          groupId: data.groupId,
          sender: "System",
          senderName: "System", 
          text: `🚫 Message from ${data.senderName} was blocked for toxic behavior`,
          timestamp: new Date()
        });
        return;
      }

      // ✅ If message is safe, broadcast to group
      socket.to(`group-${data.groupId}`).emit("group-message", data);
      
      // ✅ Save to database
      await groupMessageCollection.insertOne({
        groupId: data.groupId,
        sender: data.sender,
        senderName: data.senderName,
        text: data.text,
        timestamp: new Date()
      });

    } catch (error) {
      console.error("❌ Group message validation error:", error);
      // Fallback: allow message if check fails
      socket.to(`group-${data.groupId}`).emit("group-message", data);
      await groupMessageCollection.insertOne({
        groupId: data.groupId,
        sender: data.sender,
        senderName: data.senderName,
        text: data.text,
        timestamp: new Date()
      });
    }
  });
  
  // 📞 Handle call request
/*  socket.on("call-request", (data) => {
    if (!data.to || !data.callerId) return;

    console.log("📞 Call request:", data.callerId, "->", data.to);

    const recipient = Object.values(users).find(u => u.uid === data.to);

    if (recipient) {
      activeCalls[data.callerId] = { with: data.to, status: "calling", socketId: socket.id };
      activeCalls[data.to] = { with: data.callerId, status: "ringing", socketId: recipient.socketId };

      io.to(recipient.socketId).emit("incoming-call", {
        callerId: data.callerId,
        callerName: data.callerName || "Unknown"
      });
    } else {
      socket.emit("call-error", { message: "User is offline or unavailable" });
    }
  });

  // 📞 Handle call acceptance
  socket.on("call-accepted", (data) => {
    if (!data.to || !data.callerId) return;

    console.log("✅ Call accepted by:", data.callerId);

    const callerCall = activeCalls[data.callerId];
    if (callerCall && callerCall.socketId) {
      activeCalls[data.callerId].status = "connected";
      activeCalls[data.to].status = "connected";

      io.to(callerCall.socketId).emit("call-accepted", {
        callerId: data.callerId
      });
    }
  });

  // 📞 Handle call rejection
  socket.on("call-rejected", (data) => {
    if (!data.to || !data.callerId) return;

    console.log("❌ Call rejected by:", data.callerId);

    const callerCall = activeCalls[data.callerId];
    if (callerCall && callerCall.socketId) {
      delete activeCalls[data.callerId];
      delete activeCalls[data.to];

      io.to(callerCall.socketId).emit("call-rejected", {
        callerId: data.callerId
      });
    }
  });

  // 📞 Handle call end
  socket.on("call-ended", (data) => {
    if (!data.to || !data.callerId) return;

    console.log("📞 Call ended:", data.callerId);

    const callInfo = activeCalls[data.callerId] || activeCalls[data.to];

    if (callInfo && callInfo.socketId) {
      delete activeCalls[data.callerId];
      delete activeCalls[data.to];

      io.to(callInfo.socketId).emit("call-ended", {
        callerId: data.callerId
      });
    }
  });

  // 📞 WebRTC signaling
  socket.on("webrtc-offer", (data) => {
    if (!data.to || !data.offer) return;

    const recipient = Object.values(users).find(u => u.uid === data.to);
    if (recipient) {
      io.to(recipient.socketId).emit("webrtc-offer", {
        offer: data.offer,
        from: data.from || users[socket.id]?.uid
      });
    }
  });

  socket.on("webrtc-answer", (data) => {
    if (!data.to || !data.answer) return;

    const recipient = Object.values(users).find(u => u.uid === data.to);
    if (recipient) {
      io.to(recipient.socketId).emit("webrtc-answer", {
        answer: data.answer,
        from: data.from || users[socket.id]?.uid
      });
    }
  });

  socket.on("webrtc-ice-candidate", (data) => {
    if (!data.to || !data.candidate) return;

    const recipient = Object.values(users).find(u => u.uid === data.to);
    if (recipient) {
      io.to(recipient.socketId).emit("webrtc-ice-candidate", {
        candidate: data.candidate,
        from: data.from || users[socket.id]?.uid
      });
    }
  });
*/
  // 📞 Handle call request
socket.on("call-request", (data) => {
  if (!data.to || !data.callerId) return;

  console.log("📞 Call request:", data.callerId, "->", data.to);

  const recipient = Object.values(users).find(u => u.uid === data.to);

  if (recipient) {
    activeCalls[data.callerId] = { with: data.to, status: "calling", socketId: socket.id };
    activeCalls[data.to] = { with: data.callerId, status: "ringing", socketId: recipient.socketId };

    io.to(recipient.socketId).emit("incoming-call", {
      callerId: data.callerId,
      callerName: data.callerName || "Unknown"
    });
  } else {
    socket.emit("call-error", { message: "User is offline or unavailable" });
  }
});

// 📞 Handle call acceptance
socket.on("call-accepted", (data) => {
  if (!data.to || !data.callerId) return;

  console.log("✅ Call accepted by:", data.callerId);

  const callerCall = activeCalls[data.callerId];
  if (callerCall && callerCall.socketId) {
    activeCalls[data.callerId].status = "connected";
    activeCalls[data.to].status = "connected";

    io.to(callerCall.socketId).emit("call-accepted", {
      callerId: data.callerId
    });
  }
});

// 📞 Handle call rejection
socket.on("call-rejected", (data) => {
  if (!data.to || !data.callerId) return;

  console.log("❌ Call rejected by:", data.callerId);

  const callerCall = activeCalls[data.callerId];
  if (callerCall && callerCall.socketId) {
    delete activeCalls[data.callerId];
    delete activeCalls[data.to];

    io.to(callerCall.socketId).emit("call-rejected", {
      callerId: data.callerId
    });
  }
});

// 📞 Handle call end
socket.on("call-ended", (data) => {
  if (!data.to || !data.callerId) return;

  console.log("📞 Call ended:", data.callerId);

  const callInfo = activeCalls[data.callerId] || activeCalls[data.to];

  if (callInfo && callInfo.socketId) {
    delete activeCalls[data.callerId];
    delete activeCalls[data.to];

    io.to(callInfo.socketId).emit("call-ended", {
      callerId: data.callerId
    });
  }
});

// 📞 WebRTC signaling - YEH PART THODA CHANGE KARNA HAI
socket.on("webrtc-offer", (data) => {
  if (!data.to || !data.offer) return;

  const recipient = Object.values(users).find(u => u.uid === data.to);
  if (recipient) {
    // YEH LINE CHANGE KI HAI - 'from' field add kiya
    io.to(recipient.socketId).emit("webrtc-offer", {
      offer: data.offer,
      from: users[socket.id]?.uid || data.from  // YEH IMPORTANT HAI
    });
  }
});

socket.on("webrtc-answer", (data) => {
  if (!data.to || !data.answer) return;

  const recipient = Object.values(users).find(u => u.uid === data.to);
  if (recipient) {
    io.to(recipient.socketId).emit("webrtc-answer", {
      answer: data.answer,
      from: users[socket.id]?.uid || data.from
    });
  }
});

socket.on("webrtc-ice-candidate", (data) => {
  if (!data.to || !data.candidate) return;

  const recipient = Object.values(users).find(u => u.uid === data.to);
  if (recipient) {
    io.to(recipient.socketId).emit("webrtc-ice-candidate", {
      candidate: data.candidate,
      from: users[socket.id]?.uid || data.from
    });
  }
});

// User registration for calling (agar nahi hai toh ye add karo)
socket.on("register-call-user", (data) => {
  if (data.uid && data.name) {
    users[socket.id] = {
      uid: data.uid,
      name: data.name,
      socketId: socket.id
    };
    console.log(`User registered for calling: ${data.name} (${data.uid})`);
  }
});
  
  // 🧹 Handle disconnect
  socket.on("disconnect", () => {
    console.log("❌ Disconnected:", socket.id);

    const user = users[socket.id];
    if (user) {
      delete activeCalls[user.uid];
      delete users[socket.id];
    }
  });

  // 🆕 GROUP CHAT SOCKET EVENTS
  socket.on("join-group", (groupId) => {
    socket.join(`group-${groupId}`);
    console.log(`User joined group: ${groupId}`);
  });

  socket.on("leave-group", (groupId) => {
    socket.leave(`group-${groupId}`);
    console.log(`User left group: ${groupId}`);
  });

  socket.on("group-message", async (data) => {
    try {
      const { groupId, sender, text, senderName } = data;
      
      if (!groupId || !text) return;

      const messageData = {
        groupId,
        sender,
        senderName,
        text,
        timestamp: new Date()
      };

      await groupMessageCollection.insertOne(messageData);
      
      io.to(`group-${groupId}`).emit("group-message", messageData);
      
      // ✅ BOT AUTO-RESPONSE
      if (text.toLowerCase().includes("bot")) {
        const prompt = text.replace(/bot/gi, "").trim();
        if (prompt) {
          const reply = await generateBotReply(prompt);
          
          io.to(`group-${groupId}`).emit("group-message", {
            groupId,
            sender: "BotX",
            senderName: "BotX",
            text: reply,
            timestamp: new Date()
          });
          
          const user = await userCollection.findOne({ uid: sender });
          if (user) {
            await historyCollection.insertOne({
              name: user.name,
              prompt,
              reply,
              timestamp: new Date()
            });
          }
        }
      }
    } catch (e) {
      console.error("❌ Group Message Error:", e);
    }
  });

  // ✅ CLEAR CHAT EVENT
  socket.on("clear-chat", (data) => {
    const { groupId, clearedBy } = data;
    io.to(`group-${groupId}`).emit("chat-cleared", {
      groupId,
      clearedBy
    });
  });

  // ✅ BOT MESSAGE EVENT
  socket.on("bot-message", async (data) => {
    try {
      const { groupId, prompt, userId } = data;
      
      const reply = await generateBotReply(prompt);
      
      io.to(`group-${groupId}`).emit("bot-reply", {
        groupId,
        text: reply
      });
      
      const user = await userCollection.findOne({ uid: userId });
      if (user) {
        await historyCollection.insertOne({
          name: user.name,
          prompt,
          reply,
          timestamp: new Date()
        });
      }
    } catch (e) {
      console.error("❌ Bot message error:", e);
    }
  });

  // ✅ GROUP RENAME EVENT
  socket.on("group-rename", (data) => {
    const { groupId, newName } = data;
    io.to(`group-${groupId}`).emit("group-renamed", {
      groupId,
      newName
    });
  });

  socket.on("group-typing", (data) => {
    const { groupId, userName } = data;
    socket.to(`group-${groupId}`).emit("group-typing", userName);
  });

  socket.on("typing", (payload) => {
    if (payload && typeof payload === "object" && payload.room) socket.to(payload.room).emit("typing", payload.name || "Someone");
    else socket.broadcast.emit("typing", payload || "Someone");
  });

  socket.on("join-room", (room) => {
    if (!room) return;
    socket.join(room);
    const user = users[socket.id] || { name: "Unknown", uid: null };
    socket.to(room).emit("room-joined", user.name);
  });

  // 🌍 Global Chat
  socket.on("message", async (text) => {
    if (!text || typeof text !== "string") return;
    const user = users[socket.id] || { name: "Unknown", uid: null };
    const sender = user.name;
    io.emit("message", { sender, text });

    if (text === ">>bot") { botActive = true; io.emit("message", { sender: "System", text: "Bot is now active." }); return; }
    if (text === "<<bot") { botActive = false; io.emit("message", { sender: "System", text: "Bot is now inactive." }); return; }

    if (botActive && text.toLowerCase().includes("bot")) {
      const clean = text.replace(/bot/gi, "").trim();
      const reply = await generateBotReply(clean || "Hello");
      io.emit("message", { sender: "BotX", text: reply });
      await historyCollection.insertOne({ name: sender, prompt: clean, reply });
    }
  });

  // 🔒 Private Chat
  socket.on("private-message", async (payload) => {
    if (!payload || payload.__signal) return;

    const { room, sender, text } = payload;
    if (!room || !sender || !text) return;

    io.to(room).emit("private-message", { sender, text });

    try {
      await privateMsgCollection.insertOne({ room, sender, text, timestamp: new Date() });
    } catch (e) {
      console.error("❌ Save private message error:", e);
    }

    if (botActive && text.toLowerCase().includes("bot")) {
      const prompt = text.replace(/bot/gi, "").trim();
      const reply = await generateBotReply(prompt);
      io.to(room).emit("bot-reply", { sender: "BotX", text: reply });
      try { await historyCollection.insertOne({ name: sender, prompt, reply }); } catch {}
    }
  });

  // ✅ NEW SOCKET EVENTS FOR SETTINGS
  socket.on("logout", (data) => {
    socket.emit("logout-success");
  });
  
  socket.on("delete-account", (data) => {
    socket.emit("account-deleted");
  });

  socket.on("disconnect", () => {
    console.log("❌ Disconnected:", socket.id, users[socket.id] ? `(${users[socket.id].name}/${users[socket.id].uid})` : "");
    
    if (users[socket.id] && users[socket.id].uid) {
      const uid = users[socket.id].uid;
      if (activeCalls[uid]) {
        const otherParty = activeCalls[uid].recipient || activeCalls[uid].caller;
        if (otherParty && activeCalls[otherParty]) {
          const otherSocketId = activeCalls[otherParty].socketId;
          if (otherSocketId) {
            io.to(otherSocketId).emit("call-ended", { callerId: uid });
          }
        }
        delete activeCalls[uid];
        if (otherParty) delete activeCalls[otherParty];
      }
    }
    
    delete users[socket.id];
  });
});

// 🚀 Start Server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
