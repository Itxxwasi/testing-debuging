// ========================================
// IMPORTS AND CONFIGURATION
// ========================================
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import morgan from 'morgan';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

dotenv.config();

// ========================================
// SERVER INITIALIZATION AND CONFIGURATION
// ========================================
console.log('🚀 Starting D.Watson Pharmacy Server...');
console.log('📋 Environment:', process.env.NODE_ENV || 'development');
console.log('🔧 Port:', process.env.PORT || 5000);

const app = express();
const port = process.env.PORT || 5000;
const mongoUri = process.env.MONGODB_URI || process.env.MONGO_URL;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ========================================
// MIDDLEWARE CONFIGURATION
// ========================================
// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Allow localhost for development
    if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
      return callback(null, true);
    }
    
    // Add your production domains here
    const allowedOrigins = [
      'https://www.dwatson.online',
      'https://dwatson-db-902c7d197f9e.herokuapp.com'
    ];
    
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '1mb' }));
app.use(morgan('dev'));

// ========================================
// RATE LIMITING MIDDLEWARE
// ========================================

// Simple in-memory rate limiting
const rateLimitMap = new Map();

const rateLimit = (maxRequests = 10, windowMs = 15 * 60 * 1000) => {
  return (req, res, next) => {
    const clientId = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Clean old entries
    if (rateLimitMap.has(clientId)) {
      const requests = rateLimitMap.get(clientId).filter(time => time > windowStart);
      rateLimitMap.set(clientId, requests);
    } else {
      rateLimitMap.set(clientId, []);
    }
    
    const requests = rateLimitMap.get(clientId);
    
    if (requests.length >= maxRequests) {
      return res.status(429).json({ 
        error: 'Too many requests, please try again later',
        retryAfter: Math.ceil(windowMs / 1000)
      });
    }
    
    requests.push(now);
    next();
  };
};

// Apply rate limiting to auth routes
app.use('/api/auth', rateLimit(5, 15 * 60 * 1000)); // 5 requests per 15 minutes

// ========================================
// INPUT SANITIZATION MIDDLEWARE
// ========================================

const sanitizeInput = (req, res, next) => {
  const sanitizeString = (str) => {
    if (typeof str !== 'string') return str;
    return str
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags
      .replace(/<[^>]*>/g, '') // Remove HTML tags
      .replace(/javascript:/gi, '') // Remove javascript: protocol
      .replace(/on\w+\s*=/gi, '') // Remove event handlers
      .trim();
  };

  const sanitizeObject = (obj) => {
    if (obj === null || obj === undefined) return obj;
    if (typeof obj === 'string') return sanitizeString(obj);
    if (Array.isArray(obj)) return obj.map(sanitizeObject);
    if (typeof obj === 'object') {
      const sanitized = {};
      for (const key in obj) {
        sanitized[key] = sanitizeObject(obj[key]);
      }
      return sanitized;
    }
    return obj;
  };

  if (req.body) {
    req.body = sanitizeObject(req.body);
  }
  if (req.query) {
    req.query = sanitizeObject(req.query);
  }
  if (req.params) {
    req.params = sanitizeObject(req.params);
  }

  next();
};

app.use(sanitizeInput);


// ========================================
// DATABASE CONNECTION
// ========================================

// Validate MongoDB URI before attempting connection
if (!mongoUri) {
  console.error('❌ ERROR: MONGODB_URI environment variable is required!');
  console.error('💡 Please set MONGODB_URI environment variable with your MongoDB connection string');
  console.error('💡 Example: MONGODB_URI=mongodb://localhost:27017/your-database-name');
  process.exit(1);
}

console.log('🔄 Attempting to connect to MongoDB...');

mongoose
  .connect(mongoUri, { autoIndex: true })
  .then(() => {
    console.log('✅ MongoDB connected successfully!');
  })
  .catch((err) => {
    console.error('❌ MongoDB connection failed!');
    console.error('🔍 Error details:', err.message);
    console.error('💡 Check your MONGODB_URI environment variable');
    console.error('⚠️ Server will continue running without database connection');
    console.error('⚠️ Some features may not work until database is restored');
  });

// ========================================
// DATABASE SCHEMAS AND MODELS
// ========================================

// Branch Schema - Pharmacy locations
const BranchSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    address: { type: String, default: '' },
    phone: { type: String, default: '' },
    email: { type: String, default: '' }
  },
  { timestamps: true }
);

// Category Schema - Product categories
const CategorySchema = new mongoose.Schema(
  {
    name: { type: String, required: true, unique: true },
    description: { type: String, default: '' },
    color: { type: String, default: 'primary' }
  },
  { timestamps: true }
);

// Group Schema - User permission groups
const GroupSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, unique: true },
    description: { type: String, default: '' },
    permissions: [{ type: String }],
    isDefault: { type: Boolean, default: false }
  },
  { timestamps: true }
);

// User Schema - System users
const UserSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true },
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    groupId: { type: mongoose.Schema.Types.ObjectId, ref: 'Group', required: true },
    branches: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Branch' }],
    isActive: { type: Boolean, default: true },
    lastLogin: { type: Date }
  },
  { timestamps: true }
);

// Sale Schema - Sales transactions
const SaleSchema = new mongoose.Schema(
  {
    branchId: { type: mongoose.Schema.Types.ObjectId, ref: 'Branch', required: true },
    categoryId: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true },
    date: { type: Date, required: true },
    items: [
      {
        sku: String,
        name: String,
        quantity: Number,
        unitPrice: Number,
        cost: Number
      }
    ],
    total: { type: Number, required: true },
    costTotal: { type: Number, required: true },
    profit: { type: Number, required: true },
    category: { type: String, required: true },
    notes: { type: String, default: '' }
  },
  { timestamps: true }
);

// Settings Schema - System configuration
const SettingsSchema = new mongoose.Schema(
  {
    companyName: { type: String, default: 'D.Watson Group of Pharmacy' },
    currency: { type: String, default: 'PKR' },
    dateFormat: { type: String, default: 'DD/MM/YYYY' },
    itemsPerPage: { type: Number, default: 10 },
    defaultCostPercent: { type: Number, default: 70 }
  },
  { timestamps: true }
);

// Model Creation
const Branch = mongoose.model('Branch', BranchSchema);
const Category = mongoose.model('Category', CategorySchema);
const Group = mongoose.model('Group', GroupSchema);
const User = mongoose.model('User', UserSchema);
const Sale = mongoose.model('Sale', SaleSchema);
const Settings = mongoose.model('Settings', SettingsSchema);

// ========================================
// AUTHENTICATION CONFIGURATION
// ========================================
// Validate environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'pharmacy_sales_secret_key';

if (process.env.NODE_ENV === 'production' && JWT_SECRET === 'pharmacy_sales_secret_key') {
  console.warn('⚠️ WARNING: Using default JWT secret in production! Please set JWT_SECRET environment variable.');
}


// ========================================
// DATABASE CONNECTION CHECK MIDDLEWARE
// ========================================

// Check if database is connected
const checkDatabaseConnection = (req, res, next) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ 
      error: 'Database connection not available. Please try again later.',
      status: 'database_unavailable'
    });
  }
  next();
};

// ========================================
// AUTHENTICATION MIDDLEWARE
// ========================================

// Main Authentication Middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'Access denied. No token provided.' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const user = await User.findById(decoded.id).populate('groupId');
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid token or user not found.' });
    }
    
    if (!user.isActive) {
      return res.status(401).json({ error: 'Invalid token or inactive user.' });
    }
    
    // Ensure user has group information
    if (!user.groupId) {
      return res.status(401).json({ error: 'User has no group assigned.' });
    }
    
    // Ensure group has permissions
    if (!user.groupId.permissions || !Array.isArray(user.groupId.permissions)) {
      return res.status(401).json({ error: 'Group has no permissions defined.' });
    }
    
    
    req.user = user;
    next();
  } catch (error) {
    console.error('❌ Authentication error:', error);
    res.status(401).json({ error: 'Invalid token.' });
  }
};

// Admin Permission Middleware
const isAdmin = (req, res, next) => {
  
  // Check if user exists
  if (!req.user) {
    return res.status(401).json({ error: 'Access denied. No user found.' });
  }
  
  // Check if user has group information
  if (!req.user.groupId) {
    return res.status(403).json({ error: 'Access denied. User has no group assigned.' });
  }
  
  // Check if group has permissions
  if (!req.user.groupId.permissions || !Array.isArray(req.user.groupId.permissions)) {
    return res.status(403).json({ error: 'Access denied. Group has no permissions defined.' });
  }
  
  
  // Check if user has admin permission
  if (!req.user.groupId.permissions.includes('admin')) {
    return res.status(403).json({ error: 'Access denied. Admin privileges required.' });
  }
  
  next();
};

// ========================================
// DEBUG AND UTILITY ENDPOINTS
// ========================================

// Debug endpoint - Check user permissions
app.get('/api/debug/user', authenticate, (req, res) => {
  res.json({
    user: req.user,
    permissions: req.user.groupId.permissions,
    isAdmin: req.user.groupId.permissions.includes('admin')
  });
});

// Promote user to admin endpoint
app.post('/api/admin/promote-user', async (req, res) => {
  try {
    const { username, adminPassword } = req.body;
    
    // Verify admin password
    const expectedPassword = process.env.ADMIN_PASSWORD || 'admin123';
    if (adminPassword !== expectedPassword) {
      return res.status(403).json({ error: 'Invalid admin password' });
    }
    
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }
    
    // Find the user
    const user = await User.findOne({ username }).populate('groupId');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Find or create Admin group
    let adminGroup = await Group.findOne({ name: 'Admin' });
    if (!adminGroup) {
      adminGroup = await Group.create({
        name: 'Admin',
        description: 'System administrators with full access',
        permissions: ['admin', 'dashboard', 'categories', 'sales', 'reports', 'branches', 'groups', 'users', 'settings'],
        isDefault: true
      });
      console.log('✅ Created Admin group');
    }
    
    // Update user to Admin group
    user.groupId = adminGroup._id;
    await user.save();
    
    // Populate the updated user
    await user.populate('groupId', 'name permissions');
    
    console.log(`✅ User ${username} promoted to admin successfully`);
    
    res.json({
      message: `User ${username} has been promoted to admin`,
      user: {
        id: user._id,
        username: user.username,
        fullName: user.fullName,
        email: user.email,
        groupId: user.groupId,
        permissions: user.groupId.permissions
      }
    });
    
  } catch (error) {
    console.error('❌ Error promoting user to admin:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user by username endpoint
app.get('/api/users/username/:username', async (req, res) => {
  try {
    const { username } = req.params;
    
    const user = await User.findOne({ username }).populate('groupId', 'name permissions');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
      id: user._id,
      username: user.username,
      fullName: user.fullName,
      email: user.email,
      groupId: user.groupId,
      permissions: user.groupId.permissions,
      isActive: user.isActive
    });
    
  } catch (error) {
    console.error('❌ Error fetching user:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  const healthData = { 
    ok: true, 
    environment: process.env.NODE_ENV || 'development',
    port: port,
    timestamp: new Date().toISOString(),
    mongodb: {
      connected: mongoose.connection.readyState === 1,
      state: ['disconnected', 'connected', 'connecting', 'disconnecting'][mongoose.connection.readyState],
      host: mongoose.connection.host || 'unknown',
      port: mongoose.connection.port || 'unknown'
    },
    uptime: process.uptime(),
    memory: {
      used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB',
      total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + ' MB'
    },
    rateLimit: {
      activeConnections: rateLimitMap.size
    }
  };
  
  
  // Set appropriate status code based on database connection
  const statusCode = mongoose.connection.readyState === 1 ? 200 : 503;
  res.status(statusCode).json(healthData);
});

// ========================================
// AUTHENTICATION ROUTES
// ========================================

// User Login
app.post('/api/auth/login', checkDatabaseConnection, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    const user = await User.findOne({ username }).populate('groupId');
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    if (!user.isActive) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Fetch the user again to ensure we have the latest data
    const updatedUser = await User.findById(user._id).populate('groupId');
    
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1d' });
    
    res.json({
      token,
      user: {
        id: updatedUser._id,
        username: updatedUser.username,
        fullName: updatedUser.fullName,
        email: updatedUser.email,
        groupId: updatedUser.groupId,
        branches: updatedUser.branches,
        permissions: updatedUser.groupId.permissions
      }
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// User Logout
app.post('/api/auth/logout', authenticate, (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

// User Registration
app.post('/api/auth/signup', checkDatabaseConnection, async (req, res) => {
  try {
    const { username, fullName, email, password, confirmPassword } = req.body;
    
    
    // Validation
    if (!username || !fullName || !email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }
    
    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }
    
    // Check if database is connected
    if (mongoose.connection.readyState !== 1) {
      return res.status(500).json({ error: 'Database connection error' });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [
        { username: username },
        { email: email }
      ]
    });
    
    if (existingUser) {
      if (existingUser.username === username) {
        return res.status(409).json({ error: 'Username already exists' });
      }
      if (existingUser.email === email) {
        return res.status(409).json({ error: 'Email already registered' });
      }
    }
    
    // Get Admin group for new users (full rights)
    let adminGroup = await Group.findOne({ name: 'Admin' });
    if (!adminGroup) {
      // If Admin group doesn't exist, create it with full permissions
      adminGroup = await Group.create({
        name: 'Admin',
        description: 'System administrators with full access',
        permissions: ['admin', 'dashboard', 'categories', 'sales', 'reports', 'branches', 'groups', 'users', 'settings'],
        isDefault: true
      });
    }
    
    // Get all branches for new user (or empty array if no branches exist)
    const allBranches = await Branch.find();
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create new user with admin privileges
    const newUser = new User({
      username: username.trim(),
      fullName: fullName.trim(),
      email: email.trim().toLowerCase(),
      password: hashedPassword,
      groupId: adminGroup._id, // Assign admin group for full rights
      branches: allBranches.map(b => b._id), // Assign all branches by default
      isActive: true
    });
    
    await newUser.save();
    
    // Populate group information for response
    await newUser.populate('groupId', 'name permissions');
    
    
    // Generate JWT token
    const token = jwt.sign({ id: newUser._id }, JWT_SECRET, { expiresIn: '1d' });
    
    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: newUser._id,
        username: newUser.username,
        fullName: newUser.fullName,
        email: newUser.email,
        groupId: newUser.groupId,
        branches: newUser.branches,
        permissions: newUser.groupId.permissions
      }
    });
    
  } catch (error) {
    console.error('❌ Signup error:', error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// Get Current User Info
app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    // Fetch the user again to ensure we have the latest data
    const user = await User.findById(req.user._id).populate('groupId');
    
    res.json({
      id: user._id,
      username: user.username,
      fullName: user.fullName,
      email: user.email,
      groupId: user.groupId,
      branches: user.branches,
      permissions: user.groupId.permissions
    });
  } catch (error) {
    console.error('❌ Get user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ========================================
// SETTINGS API ROUTES
// ========================================

// Get System Settings
app.get('/api/settings', authenticate, async (req, res) => {
  try {
    let settings = await Settings.findOne();
    if (!settings) {
      settings = await Settings.create({});
    }
    res.json(settings);
  } catch (error) {
    console.error('Error fetching settings:', error);
    res.status(500).json({ error: error.message });
  }
});

// Update System Settings
app.put('/api/settings', authenticate, isAdmin, async (req, res) => {
  try {
    const update = {
      companyName: req.body.companyName ?? 'D.Watson Group of Pharmacy',
      currency: req.body.currency ?? 'PKR',
      dateFormat: req.body.dateFormat ?? 'DD/MM/YYYY',
      itemsPerPage: Number(req.body.itemsPerPage ?? 10),
      defaultCostPercent: req.body.defaultCostPercent !== undefined ? Number(req.body.defaultCostPercent) : undefined
    };
    
    // Remove undefined to avoid overwriting with undefined
    Object.keys(update).forEach((k) => update[k] === undefined && delete update[k]);
    
    const settings = await Settings.findOneAndUpdate({}, update, { new: true, upsert: true });
    res.json(settings);
  } catch (error) {
    console.error('Error updating settings:', error);
    res.status(400).json({ error: error.message });
  }
});

// ========================================
// BRANCHES API ROUTES
// ========================================

// Get All Branches
app.get('/api/branches', authenticate, checkDatabaseConnection, async (req, res) => {
  try {
    // If user is not admin, only return assigned branches
    const filter = {};
    if (!req.user.groupId.permissions.includes('admin')) {
      filter._id = { $in: req.user.branches };
    }
    
    const branches = await Branch.find(filter).sort({ createdAt: -1 });
    res.json(branches);
  } catch (error) {
    console.error('❌ Error fetching branches:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Create New Branch
app.post('/api/branches', authenticate, isAdmin, checkDatabaseConnection, async (req, res) => {
  try {
    const name = (req.body.name || '').trim();
    if (!name) return res.status(400).json({ error: 'Name is required' });
    // Enforce unique name (case-insensitive)
    const exists = await Branch.findOne({ name: { $regex: `^${name}$`, $options: 'i' } });
    if (exists) return res.status(409).json({ error: 'Branch with this name already exists' });
    const branch = await Branch.create({ ...req.body, name });
    res.status(201).json(branch);
  } catch (error) {
    console.error('❌ Error creating branch:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Update Branch
app.put('/api/branches/:id', authenticate, isAdmin, checkDatabaseConnection, async (req, res) => {
  try {
    const id = req.params.id;
    const payload = { ...req.body };

    // Normalize name if provided
    if (payload.name !== undefined && payload.name !== null) {
      payload.name = String(payload.name).trim();

      // Fetch current branch to compare names
      const current = await Branch.findById(id);
      if (!current) {
        return res.status(404).json({ error: 'Branch not found' });
      }

      // Simple case-insensitive comparison
      const currentName = String(current.name || '').toLowerCase().trim();
      const newName = payload.name.toLowerCase().trim();
      const nameChanged = currentName !== newName;


      // Only enforce uniqueness if the name is actually changing
      if (nameChanged) {
        const exists = await Branch.findOne({
          _id: { $ne: id },
          name: { $regex: `^${payload.name}$`, $options: 'i' }
        });
        if (exists) {
          return res.status(409).json({ error: 'Branch with this name already exists' });
        }
      }
    }
    
    const updated = await Branch.findByIdAndUpdate(id, payload, { new: true });
    if (!updated) {
      return res.status(404).json({ error: 'Branch not found' });
    }
    
    res.json(updated);
  } catch (error) {
    console.error('❌ Error updating branch:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Delete Branch
app.delete('/api/branches/:id', authenticate, isAdmin, checkDatabaseConnection, async (req, res) => {
  try {
    const branch = await Branch.findByIdAndDelete(req.params.id);
    if (!branch) {
      return res.status(404).json({ error: 'Branch not found' });
    }
    // Also delete all sales associated with this branch
    await Sale.deleteMany({ branchId: req.params.id });
    // Remove branch from all users
    await User.updateMany(
      { branches: req.params.id },
      { $pull: { branches: req.params.id } }
    );
    res.json({ ok: true });
  } catch (error) {
    console.error('❌ Error deleting branch:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// ========================================
// CATEGORIES API ROUTES
// ========================================

// Get All Categories
app.get('/api/categories', authenticate, async (req, res) => {
  try {
    const categories = await Category.find().sort({ createdAt: -1 });
    res.json(categories);
  } catch (error) {
    console.error('❌ Error fetching categories:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Create New Category
app.post('/api/categories', authenticate, isAdmin, checkDatabaseConnection, async (req, res) => {
  try {
    const { name, description, color } = req.body;
    
    // Check if category with same name already exists
    const existingCategory = await Category.findOne({ 
      name: { $regex: new RegExp(`^${name}$`, 'i') } 
    });
    
    if (existingCategory) {
      return res.status(400).json({ 
        error: `A category with the name "${name}" already exists. Please choose a different name.` 
      });
    }
    
    const category = await Category.create(req.body);
    res.status(201).json(category);
  } catch (error) {
    console.error('❌ Error creating category:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Update Category
app.put('/api/categories/:id', authenticate, isAdmin, checkDatabaseConnection, async (req, res) => {
  try {
    const { name, description, color } = req.body;
    
    // Check if another category with the same name exists (excluding current category)
    const existingCategory = await Category.findOne({ 
      name: { $regex: new RegExp(`^${name}$`, 'i') }, 
      _id: { $ne: req.params.id } 
    });
    
    if (existingCategory) {
      return res.status(400).json({ 
        error: `A category with the name "${name}" already exists. Please choose a different name.` 
      });
    }
    
    const updated = await Category.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!updated) {
      return res.status(404).json({ error: 'Category not found' });
    }
    res.json(updated);
  } catch (error) {
    console.error('❌ Error updating category:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Delete Category
app.delete('/api/categories/:id', authenticate, isAdmin, checkDatabaseConnection, async (req, res) => {
  try {
    const category = await Category.findByIdAndDelete(req.params.id);
    if (!category) {
      return res.status(404).json({ error: 'Category not found' });
    }
    res.json({ ok: true });
  } catch (error) {
    console.error('❌ Error deleting category:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// ========================================
// GROUPS API ROUTES
// ========================================

// Get All Groups
app.get('/api/groups', authenticate, isAdmin, async (req, res) => {
  try {
    const groups = await Group.find().sort({ createdAt: -1 });
    res.json(groups);
  } catch (error) {
    console.error('❌ Error fetching groups:', error);
    res.status(500).json({ error: error.message });
  }
});

// Create New Group
app.post('/api/groups', authenticate, isAdmin, checkDatabaseConnection, async (req, res) => {
  try {
    const { name, description, permissions } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Group name is required' });
    }
    
    // Check if group with same name already exists
    const existingGroup = await Group.findOne({ name });
    if (existingGroup) {
      return res.status(400).json({ error: 'Group with this name already exists' });
    }
    
    const group = new Group({ name, description, permissions });
    await group.save();
    
    res.status(201).json(group);
  } catch (error) {
    console.error('Error creating group:', error);
    res.status(500).json({ error: error.message });
  }
});

// Update Group
app.put('/api/groups/:id', authenticate, isAdmin, checkDatabaseConnection, async (req, res) => {
  try {
    const { name, description, permissions } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Group name is required' });
    }
    
    // Check if group with same name already exists (excluding current group)
    const existingGroup = await Group.findOne({ 
      name, 
      _id: { $ne: req.params.id } 
    });
    
    if (existingGroup) {
      return res.status(400).json({ error: 'Group with this name already exists' });
    }
    
    const group = await Group.findByIdAndUpdate(
      req.params.id,
      { name, description, permissions },
      { new: true }
    );
    
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    
    res.json(group);
  } catch (error) {
    console.error('Error updating group:', error);
    res.status(500).json({ error: error.message });
  }
});

// Delete Group
app.delete('/api/groups/:id', authenticate, isAdmin, checkDatabaseConnection, async (req, res) => {
  try {
    const group = await Group.findByIdAndDelete(req.params.id);
    
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    
    // Update all users with this group to have no group
    await User.updateMany(
      { groupId: req.params.id },
      { $unset: { groupId: 1 } }
    );
    
    res.json({ message: 'Group deleted successfully' });
  } catch (error) {
    console.error('Error deleting group:', error);
    res.status(500).json({ error: error.message });
  }
});

// ========================================
// USERS API ROUTES
// ========================================

// Get All Users
app.get('/api/users', authenticate, isAdmin, async (req, res) => {
  try {
    const users = await User.find()
      .populate('groupId', 'name permissions')
      .sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    console.error('❌ Error fetching users:', error);
    res.status(500).json({ error: error.message });
  }
});

// Create New User
app.post('/api/users', authenticate, isAdmin, checkDatabaseConnection, async (req, res) => {
  try {
    const { username, fullName, email, password, groupId, branches } = req.body;
    
    if (!username || !fullName || !email || !password || !groupId) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Check if user with same username or email already exists
    const existingUser = await User.findOne({
      $or: [
        { username },
        { email }
      ]
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'User with this username or email already exists' });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    const user = new User({
      username,
      fullName,
      email,
      password: hashedPassword,
      groupId,
      branches
    });
    
    await user.save();
    
    // Populate group for response
    await user.populate('groupId', 'name permissions');
    
    res.status(201).json(user);
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ error: error.message });
  }
});

// Update User
app.put('/api/users/:id', authenticate, isAdmin, checkDatabaseConnection, async (req, res) => {
  try {
    const { username, fullName, email, password, groupId, branches, isActive } = req.body;
    
    if (!username || !fullName || !email || !groupId) {
      return res.status(400).json({ error: 'Username, full name, email, and group are required' });
    }
    
    // Check if user with same username or email already exists (excluding current user)
    const existingUser = await User.findOne({
      $or: [
        { username },
        { email }
      ],
      _id: { $ne: req.params.id }
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'User with this username or email already exists' });
    }
    
    const updateData = {
      username,
      fullName,
      email,
      groupId,
      branches,
      isActive
    };
    
    // Only update password if provided
    if (password) {
      const salt = await bcrypt.genSalt(10);
      updateData.password = await bcrypt.hash(password, salt);
    }
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    ).populate('groupId', 'name permissions');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(user);
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ error: error.message });
  }
});

// Delete User
app.delete('/api/users/:id', authenticate, isAdmin, checkDatabaseConnection, async (req, res) => {
  try {
    // Prevent users from deleting themselves
    if (req.user._id.toString() === req.params.id) {
      return res.status(400).json({ error: 'You cannot delete your own account' });
    }
    
    const user = await User.findByIdAndDelete(req.params.id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: error.message });
  }
});

// ========================================
// SALES API ROUTES
// ========================================

// Get All Sales
app.get('/api/sales', authenticate, async (req, res) => {
  try {
    const filter = {};
    
    // Build filter from query parameters
    if (req.query.branchId && req.query.branchId !== 'undefined' && req.query.branchId.trim() !== '') {
      filter.branchId = req.query.branchId;
    }
    
    if (req.query.categoryId && req.query.categoryId !== 'undefined' && req.query.categoryId.trim() !== '') {
      filter.categoryId = req.query.categoryId;
    }
    
    if (req.query.from || req.query.to) {
      filter.date = {};
      if (req.query.from) {
        filter.date.$gte = new Date(req.query.from);
      }
      if (req.query.to) {
        filter.date.$lte = new Date(req.query.to);
      }
    }
    
    // If user is not admin, filter by user's assigned branches
    if (!req.user.groupId.permissions.includes('admin')) {
      filter.branchId = { $in: req.user.branches };
    }
    
    const sales = await Sale.find(filter)
      .sort({ date: -1 })
      .populate('branchId', 'name')
      .populate('categoryId', 'name');
    
    res.json(sales);
  } catch (error) {
    console.error('❌ Error fetching sales:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Create New Sale
app.post('/api/sales', authenticate, checkDatabaseConnection, async (req, res) => {
  try {
    // Copy request data
    const data = { ...req.body };

    // If category string missing, fetch from Category model
    if (!data.category && data.categoryId) {
      try {
        const cat = await Category.findById(data.categoryId);
        data.category = cat ? cat.name : 'Unknown';
      } catch (err) {
        console.warn('⚠️ Could not find category for ID:', data.categoryId);
        data.category = 'Unknown';
      }
    }

    // Check if user has access to this branch
    if (!req.user.groupId.permissions.includes('admin') && !req.user.branches.includes(data.branchId)) {
      return res.status(403).json({ error: 'Access denied. You do not have permission to access this branch.' });
    }

    // Create sale using fixed data
    const sale = await Sale.create(data);

    // Populate branch & category references before sending response
    const populatedSale = await Sale.findById(sale._id)
      .populate('branchId', 'name')
      .populate('categoryId', 'name');

    res.status(201).json(populatedSale);
  } catch (error) {
    console.error('❌ Error creating sale:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Update Sale
app.put('/api/sales/:id', authenticate, checkDatabaseConnection, async (req, res) => {
  try {
    // Check if user has access to this branch
    if (!req.user.groupId.permissions.includes('admin') && !req.user.branches.includes(req.body.branchId)) {
      return res.status(403).json({ error: 'Access denied. You do not have permission to access this branch.' });
    }

    const updated = await Sale.findByIdAndUpdate(req.params.id, req.body, { new: true })
      .populate('branchId', 'name')
      .populate('categoryId', 'name');
    
    if (!updated) {
      return res.status(404).json({ error: 'Sale not found' });
    }
    
    res.json(updated);
  } catch (error) {
    console.error('❌ Error updating sale:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Delete Sale
app.delete('/api/sales/:id', authenticate, checkDatabaseConnection, async (req, res) => {
  try {
    // Check if user has access to this sale's branch
    const sale = await Sale.findById(req.params.id);
    if (!sale) {
      return res.status(404).json({ error: 'Sale not found' });
    }
    
    if (!req.user.groupId.permissions.includes('admin') && !req.user.branches.includes(sale.branchId)) {
      return res.status(403).json({ error: 'Access denied. You do not have permission to access this branch.' });
    }

    const deleted = await Sale.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
  } catch (error) {
    console.error('❌ Error deleting sale:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// ========================================
// ADMIN UTILITY ROUTES
// ========================================

// Admin Delete Action
app.post('/api/admin/delete', async (req, res) => {
  try {
    const { resource, id, password } = req.body || {};
    const expected = String(process.env.ADMIN_PASSWORD || '');
    const provided = String(password || '');
    
    if (!expected) {
      console.error('🔐 Admin password not configured on server');
      return res.status(500).json({ error: 'Admin password not configured on server' });
    }
    
    if (provided.trim() !== expected.trim()) {
      console.warn('🔒 Admin auth failed: provided.length=%d expected.length=%d', provided.length, expected.length);
      return res.status(403).json({ error: 'Invalid admin password' });
    }

    if (!resource || !id) {
      return res.status(400).json({ error: 'resource and id are required' });
    }

    let deleted = null;
    if (resource === 'sales') {
      deleted = await Sale.findByIdAndDelete(id);
    } else if (resource === 'branches') {
      deleted = await Branch.findByIdAndDelete(id);
      await Sale.deleteMany({ branchId: id });
      await User.updateMany(
        { branches: id },
        { $pull: { branches: id } }
      );
    } else if (resource === 'categories') {
      deleted = await Category.findByIdAndDelete(id);
    } else if (resource === 'groups') {
      deleted = await Group.findByIdAndDelete(id);
      await User.updateMany(
        { groupId: id },
        { $unset: { groupId: 1 } }
      );
    } else if (resource === 'users') {
      deleted = await User.findByIdAndDelete(id);
    } else {
      return res.status(400).json({ error: 'Unknown resource type' });
    }

    if (!deleted) {
      return res.status(404).json({ error: 'Record not found' });
    }
    
    return res.json({ ok: true });
  } catch (error) {
    console.error('❌ Admin delete error:', error.message);
    return res.status(500).json({ error: error.message });
  }
});

// Admin Update Action
app.post('/api/admin/update', async (req, res) => {
  try {
    const { resource, id, payload, password } = req.body || {};
    const expected = String(process.env.ADMIN_PASSWORD || '');
    const provided = String(password || '');
    
    if (!expected) {
      console.error('🔐 Admin password not configured on server');
      return res.status(500).json({ error: 'Admin password not configured on server' });
    }
    
    if (provided.trim() !== expected.trim()) {
      console.warn('🔒 Admin auth failed (update): provided.length=%d expected.length=%d', provided.length, expected.length);
      return res.status(403).json({ error: 'Invalid admin password' });
    }

    if (!resource || !id || !payload) {
      return res.status(400).json({ error: 'resource, id and payload are required' });
    }

    let updated = null;
    if (resource === 'sales') {
      updated = await Sale.findByIdAndUpdate(id, payload, { new: true })
        .populate('branchId', 'name')
        .populate('categoryId', 'name');
    } else if (resource === 'branches') {
      updated = await Branch.findByIdAndUpdate(id, payload, { new: true });
    } else if (resource === 'categories') {
      updated = await Category.findByIdAndUpdate(id, payload, { new: true });
    } else if (resource === 'groups') {
      updated = await Group.findByIdAndUpdate(id, payload, { new: true });
    } else if (resource === 'users') {
      // Hash password if provided
      if (payload.password) {
        const salt = await bcrypt.genSalt(10);
        payload.password = await bcrypt.hash(payload.password, salt);
      }
      updated = await User.findByIdAndUpdate(id, payload, { new: true })
        .populate('groupId', 'name permissions');
    } else {
      return res.status(400).json({ error: 'Unknown resource type' });
    }

    if (!updated) {
      return res.status(404).json({ error: 'Record not found' });
    }
    
    return res.json(updated);
  } catch (error) {
    console.error('❌ Admin update error:', error.message);
    return res.status(500).json({ error: error.message });
  }
});

// ========================================
// DATABASE SEEDING FUNCTION
// ========================================

// Seed default data - Creates initial data for the system
async function seedDefaultData() {
  
  try {
    // Seed branches
    const branchCount = await Branch.estimatedDocumentCount();
    
    if (branchCount === 0) {
      const defaultBranches = [
        { name: 'D WATSON PWD', address: '' },
        { name: 'D WATSON F6', address: '' },
        { name: 'D WATSON GUJJAR KHAN', address: '' },
        { name: 'D WATSON CHANDNI CHOWK', address: '' },
        { name: 'D WATSON ATTOCK', address: '' },
        { name: 'D WATSON GHORI TOWN', address: '' },
        { name: 'D WATSON G 15', address: '' }
      ];
      await Branch.insertMany(defaultBranches);
    } else {
    }

    // Seed categories
    const categoryCount = await Category.estimatedDocumentCount();
    if (categoryCount === 0) {
      const defaultCategories = [
        { name: 'MEDICINE NEUTRA', description: 'Neutral medicine category', color: 'primary' },
        { name: 'MEDICINE AIMS', description: 'AIMS medicine category', color: 'success' },
        { name: 'COSTMAIES', description: 'Costmaies category', color: 'info' }
      ];
      await Category.insertMany(defaultCategories);
    }
    
    // Seed groups - FIXED to ensure admin permissions are set correctly
    const groupCount = await Group.estimatedDocumentCount();
    if (groupCount === 0) {
      const defaultGroups = [
        {
          name: 'Admin',
          description: 'System administrators with full access',
          permissions: ['admin', 'dashboard', 'categories', 'sales', 'reports', 'branches', 'groups', 'users', 'settings'],
          isDefault: true
        },
        {
          name: 'Sales',
          description: 'Sales staff with access to sales entry and reports',
          permissions: ['dashboard', 'sales', 'reports'],
          isDefault: true
        },
        {
          name: 'Manager',
          description: 'Branch managers with access to dashboard and reports only',
          permissions: ['dashboard', 'reports'],
          isDefault: true
        }
      ];
      await Group.insertMany(defaultGroups);
      // Verify admin group was created correctly
      const adminGroup = await Group.findOne({ name: 'Admin' });
      if (!adminGroup) {
        console.error('❌ Admin group not found after creation');
      }
    } else {
      
      // Check if admin group exists and has correct permissions
      const adminGroup = await Group.findOne({ name: 'Admin' });
      if (adminGroup) {
        // Ensure admin group has admin permission
        if (!adminGroup.permissions.includes('admin')) {
          adminGroup.permissions.push('admin');
          await adminGroup.save();
        }
      } else {
        console.error('❌ Admin group not found');
      }
      
      // Update Manager group to have only dashboard and reports permissions
      const managerGroup = await Group.findOne({ name: 'Manager' });
      if (managerGroup) {
        // Update Manager group to only have dashboard and reports permissions
        const correctManagerPermissions = ['dashboard', 'reports'];
        const needsUpdate = JSON.stringify(managerGroup.permissions.sort()) !== JSON.stringify(correctManagerPermissions.sort());
        
        if (needsUpdate) {
          managerGroup.permissions = correctManagerPermissions;
          managerGroup.description = 'Branch managers with access to dashboard and reports only';
          await managerGroup.save();
        }
      } else {
        console.error('❌ Manager group not found');
      }
    }
    
    // Seed admin user - FIXED to ensure it references the admin group
    const userCount = await User.estimatedDocumentCount();
    if (userCount === 0) {
      
      // Find the admin group
      const adminGroup = await Group.findOne({ name: 'Admin' });
      if (!adminGroup) {
        console.error('❌ Admin group not found, cannot create admin user');
        return;
      }
      
      
      // Get all branches
      const allBranches = await Branch.find();
      if (allBranches.length === 0) {
        console.error('❌ No branches found, cannot create admin user');
        return;
      }
      
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash('admin123', salt);
      
      const adminUser = new User({
        username: 'admin',
        fullName: 'System Administrator',
        email: 'admin@dwatson.com',
        password: hashedPassword,
        groupId: adminGroup._id,
        branches: allBranches.map(b => b._id)
      });
      
      await adminUser.save();
      
      // Verify admin user was created correctly
      const createdUser = await User.findById(adminUser._id).populate('groupId');
      if (createdUser) {
      } else {
        console.error('❌ Admin user not found after creation');
      }
    } else {
      
      // Check if admin user exists and has correct group
      const adminUser = await User.findOne({ username: 'admin' }).populate('groupId');
      if (adminUser) {
        
        // Ensure admin user has admin permission
        if (!adminUser.groupId.permissions.includes('admin')) {
          adminUser.groupId.permissions.push('admin');
          await adminUser.groupId.save();
        }
      } else {
        console.error('❌ Admin user not found');
      }
    }
    
  } catch (error) {
    console.error('❌ Seed error:', error.message);
    console.error('⚠️ Seeding failed, but server will continue running');
    console.error('⚠️ You may need to manually create admin user and groups');
  }
}

// ========================================
// STATIC FILE SERVING
// ========================================

// Serve static frontend files
const clientDir = path.resolve(__dirname, '..');
app.use('/', express.static(clientDir));

// ========================================
// SERVER STARTUP
// ========================================

// Start server immediately - not dependent on database
app.listen(port, () => {
  console.log('🚀 D.Watson Pharmacy Server Started Successfully!');
  console.log(`🌐 Server listening on port: ${port}`);
  console.log(`🏠 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log('✅ All systems ready! API endpoints active.');
});

// Start seeding when database is ready (if connected)
mongoose.connection.once('open', () => {
  seedDefaultData();
});

// ========================================
// ERROR HANDLING MIDDLEWARE
// ========================================

// Global error handler
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler for API routes and frontend
app.use('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    res.status(404).json({ error: 'API endpoint not found', path: req.path });
  } else {
    // For non-API routes, serve the frontend
    res.sendFile(path.join(clientDir, 'index.html'));
  }
});




