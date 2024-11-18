const express = require('express');
const mongoose = require('mongoose');
const { MongoClient } = require('mongodb');
const { ObjectId } = mongoose.Types; 
const cors = require('cors');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
dotenv.config();

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

app.use(cors({
  origin: '*', 
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'] 
}));

const port = process.env.PORT || 3000;
const dbUri = 'mongodb://localhost:27017/watch';
const client = new MongoClient(dbUri);

mongoose.connect(dbUri)
  .then(() => {
    console.log('MongoDB connected successfully');
    startServer();
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1); 
  });

function startServer() {
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
}

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//loginuser

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Customer' },
  phone: { type: String },
  address: { type: String },
  province: { type: String },
  district: { type: String },
  tambon: { type: String },
  postal_code: { type: String },
});


userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

const User = mongoose.model('User', userSchema);

app.post('/users/register', async (req, res) => {
  const { username, password, email, customerId = null } = req.body;
  if (!username || !password || !email) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ message: 'Password must be at least 8 characters long' });
  }
  const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z]).{8,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({
      message: 'Password must contain at least one uppercase letter, one number, and one special character'
    });
  }
  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ message: 'Username or email already exists' });
    }
    const newCustomerId = customerId ? mongoose.Types.ObjectId(customerId) : new mongoose.Types.ObjectId();
    const user = new User({
      username,
      password, 
      email,
      customerId: newCustomerId,
    });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/users/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({
      token,
      email: user.email,
      customerId: user.customerId ? user.customerId.toString() : null,
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ message: 'Server error' });
  }
});


app.post('/users/resetpassword', async (req, res) => {
  const { email, username, oldPassword, newPassword } = req.body;

  if (!email || !username || !oldPassword || !newPassword) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({ message: 'New password must be at least 8 characters long' });
  }

  const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z]).{8,}$/;
  if (!passwordRegex.test(newPassword)) {
    return res.status(400).json({
      message: 'Password must contain at least one uppercase letter, one number, and one special character'
    });
  }

  try {
    const user = await User.findOne({ email, username });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const match = await bcrypt.compare(oldPassword, user.password);
    console.log('Old password match result:', match);
    if (!match) {
      return res.status(401).json({ message: 'Old password is incorrect' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    console.log('Password has been updated for user:', user.username);
    return res.status(200).json({ message: 'Password has been reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    return res.status(500).json({ message: 'Error resetting password' });
  }
});

app.get('/users/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json({
      username: user.username,
      email: user.email,
      phone: user.phone,
      address: user.address,
      province: user.province,
      district: user.district,
      tambon: user.tambon,
      postal_code: user.postal_code,
    });
  } catch (error) {
    console.error('Error fetching user data:', error.message);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/users/me', authenticateToken, async (req, res) => {
  try {
    const { phone, address, province, district, tambon, postal_code } = req.body;
    console.log('Request body:', req.body);

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    console.log('User before update:', user);

    user.phone = phone;
    user.address = address;
    user.province = province;
    user.district = district;
    user.tambon = tambon;
    user.postal_code = postal_code;

    await user.save();

    console.log('User after save:', user);

    res.status(200).json({ message: 'Shipping information updated successfully' });
  } catch (error) {
    console.error('Error updating shipping information:', error.message);
    res.status(500).json({ message: 'Server error' });
  }
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401); 

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); 
    req.user = user; 
    next();
  });
}

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//adminmes
/*
const messageSchema = new mongoose.Schema({
  message: {
    type: String,
    required: true,
  },
  timestamp: {
    type: Date,
    required: true,
    default: Date.now,
  },
  user: {
    type: String,
    required: true,
  },
  read: {
    type: Boolean,
    default: false,
  },
});

const MessageModel = mongoose.model('Message', messageSchema);

app.post('/admin/messages', async (req, res) => {
  const { message, timestamp, user } = req.body;

  if (!message || !user) {
    return res.status(400).send({ success: false, error: 'Missing required fields' });
  }

  try {
    const newMessage = new MessageModel({ message, timestamp, user });
    await newMessage.save();
    res.status(200).send({ success: true });
  } catch (error) {
    res.status(500).send({ success: false, error: 'Error saving message' });
  }
});

app.get('/messages/:user', async (req, res) => {
  const { user } = req.params;
  try {
    const messages = await MessageModel.find({ user }).sort({ timestamp: 1 });
    res.status(200).send(messages);
  } catch (error) {
    res.status(500).send({ success: false, error: 'Error fetching messages' });
  }
});
*/

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//chatbot

app.post('/chatbot/search', async (req, res) => {
  const { question } = req.body;
  console.log('Received question for search:', question);
  if (!question || typeof question !== 'string' || question.trim() === '') {
    return res.status(400).json({ message: 'คำถามไม่ถูกต้อง' });
  }
  try {
    await client.connect();
    const database = client.db('watch');
    const chatbotCollection = database.collection('chatbot');
    let response = await chatbotCollection.findOne({ $text: { $search: question } });
    if (!response) {
      response = await chatbotCollection.findOne({ คำถาม: { $regex: new RegExp(question, 'i') } });
    }
    if (response) {
      res.status(200).json({ answer: response.คำตอบ });
    } else {
      res.status(200).json({ answer: 'ขออภัย ไม่พบคำตอบที่ต้องการ กรุณาลองถามคำถามอื่น' });
    }
  } catch (error) {
    console.error('Error fetching response from MongoDB:', error);
    res.status(500).json({ message: 'Server error' });
  } finally {
    await client.close();
  }
});

app.post('/chatbot', async (req, res) => {
  const { คำถาม, คำตอบ } = req.body;
  if (!คำถาม || !คำตอบ) {
    return res.status(400).json({ error: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
  }
  try {
    await client.connect();
    const database = client.db('watch');
    const chatbotCollection = database.collection('chatbot');
    const newChatbot = { คำถาม, คำตอบ };
    await chatbotCollection.insertOne(newChatbot);
    res.status(201).json(newChatbot);
  } catch (error) {
    console.error('Error adding chatbot:', error);
    res.status(500).json({ error: 'เพิ่มคำถามไม่สำเร็จ' });
  } finally {
    await client.close();
  }
});

app.get('/chatbot', async (req, res) => {
  try {
    await client.connect();
    const database = client.db('watch');
    const collection = database.collection('chatbot');
    const data = await collection.find().toArray();
    res.status(200).json(data);
  } catch (error) {
    console.error('Error fetching chatbot data:', error);
    res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลจากฐานข้อมูล' });
  } finally {
    await client.close();
  }
});

app.put('/chatbot/:id', async (req, res) => {
  const id = req.params.id;
  const updatedData = req.body;
  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ message: 'ID คำถามไม่ถูกต้อง' });
  }
  try {
    await client.connect();
    const database = client.db('watch');
    const chatbotCollection = database.collection('chatbot');
    const result = await chatbotCollection.updateOne({ _id: new ObjectId(id) }, { $set: updatedData });
    if (result.modifiedCount > 0) {
      res.status(200).send({ message: 'Chatbot updated successfully' });
    } else {
      res.status(404).send({ message: 'Chatbot not found' });
    }
  } catch (error) {
    res.status(500).send({ message: 'An error occurred', error: error.message });
  } finally {
    await client.close();
  }
});


//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//products

const productSchema = new mongoose.Schema({
  Brand: String,
  Serial_number: String,
  Size: String,
  Color: String,
  Material: String,
  Features: String,  
  Condition: String,
  Stock_status: String,
  Images: String,
  Warranty: String,
  Price: String,
});

const Product = mongoose.model('Product', productSchema);

app.get('/products', async (req, res) => {
  const searchQuery = req.query.search || '';
  try {
    const products = await Product.find({
      $or: [
        { Brand: { $regex: searchQuery, $options: 'i' } },
        { Serial_number: { $regex: searchQuery, $options: 'i' } }
      ]
    });
    res.json(products);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/products/brand/:brand', async (req, res) => {
  const { brand } = req.params;
  try {
    const products = await Product.find({ Brand: { $regex: `^${brand}`, $options: 'i' } }); 
    res.json(products);
  } catch (error) {
    console.error('Error fetching products by brand:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/products', async (req, res) => {
  const { Brand, Serial_number, Size, Color, Material, Features, Condition, Stock_status, Images, Warranty, Price } = req.body;

  if (!Brand || !Serial_number || !Size || !Color || !Material || !Features || !Condition || !Stock_status || !Images || !Warranty || !Price) {
    return res.status(400).json({ message: 'ข้อมูลไม่ครบถ้วน' });
  }

  try {
    const newProduct = new Product({ Brand, Serial_number, Size, Color, Material, Features, Condition, Stock_status, Images, Warranty, Price });
    await newProduct.save();
    res.status(201).json({ message: 'เพิ่มสินค้าสำเร็จ' });
  } catch (error) {
    console.error('Error adding product:', error);
    res.status(500).json({ message: 'เพิ่มสินค้าไม่สำเร็จ' });
  }
});

app.put('/products/:id', async (req, res) => {
  const { id } = req.params;
  const { Brand, Serial_number, Size, Color, Material, Features, Condition, Stock_status, Images, Warranty, Price } = req.body;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ message: 'ID สินค้าไม่ถูกต้อง' });
  }

  try {
    const updatedProduct = await Product.findByIdAndUpdate(
      id,
      { Brand, Serial_number, Size, Color, Material, Features, Condition, Stock_status, Images, Warranty, Price },
      { new: true }
    );

    if (!updatedProduct) {
      return res.status(404).json({ message: 'ไม่พบสินค้านี้' });
    }

    res.json({ message: 'แก้ไขสินค้าสำเร็จ', product: updatedProduct });
  } catch (error) {
    console.error('Error updating product:', error);
    res.status(500).json({ message: 'แก้ไขสินค้าไม่สำเร็จ' });
  }
});

// DELETE ลบสินค้า
app.delete('/products/:id', async (req, res) => {
  const { id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ message: 'ID สินค้าไม่ถูกต้อง' });
  }

  try {
    const deletedProduct = await Product.findByIdAndDelete(id);

    if (!deletedProduct) {
      return res.status(404).json({ message: 'ไม่พบสินค้านี้' });
    }

    res.json({ message: 'ลบสินค้าสำเร็จ' });
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(500).json({ message: 'ลบสินค้าไม่สำเร็จ' });
  }
});
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//order

const orderSchema = new mongoose.Schema({
  orderId: { type: String, required: true },
  products: [{
    quantity: { type: Number, required: true, default: 1 },
    price: { type: Number, required: true },
    images: { type: [String], default: [] },
    brand: { type: String },
    serialNumber: { type: String },
  }],
  shippingInfo: {
    name: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String, required: true },
    address: { type: String, required: true },
    province: { type: String, required: true },
    district: { type: String, required: true },
    tambon: { type: String, required: true },
    postalCodemain: { type: String, required: true },
  },
  slip: { type: String }, 
  trackingNumber: { type: String }, 
  status: { type: String, default: 'pending' },
  addedAt: { type: Date, default: Date.now },
});

const Order = mongoose.model('Order', orderSchema);

const generateShortOrderId = () => {
  return 'ORD-' + Math.random().toString(36).substr(2, 8).toUpperCase();
};

const generateTrackingNumber = () => {
  return 'TK-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5).toUpperCase(); 
};

app.post('/orders', async (req, res) => {
  console.log('Received order data:', req.body);
  
  const { products, shippingInfo, slip } = req.body;
  if (!products || products.length === 0 || !shippingInfo || !shippingInfo.postalCodemain) {
    return res.status(400).json({ message: 'Missing required fields' });
  }
  for (let key in shippingInfo) {
    if (typeof shippingInfo[key] === 'string') {
      shippingInfo[key] = shippingInfo[key].trim();
    }
  }

  try {
    const orderId = generateShortOrderId(); 
    const trackingNumber = generateTrackingNumber();

    console.log('Generated orderId:', orderId);
    console.log('Generated tracking number:', trackingNumber);

    const newOrder = new Order({
      orderId,  
      products: products.map(product => ({
        quantity: product.quantity || 1,
        price: product.price || 0,
        images: product.images || [],
        brand: product.brand || 'Unknown',
        serialNumber: product.serialNumber || 'N/A',
      })),
      shippingInfo,
      slip: slip || null, 
      trackingNumber,
      addedAt: new Date(),
    });

    await newOrder.save();
    console.log('Order saved to database:', newOrder);

    res.status(201).json({ message: 'Order created successfully!', order: newOrder });
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.get('/orders', async (req, res) => {
  const { status } = req.query;
  try {
    let query = {};
    if (status) {
      query.status = status; 
    }
    const orders = await Order.find(query); 
    res.status(200).json(orders);
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/orders/:orderId/received', async (req, res) => {
  try {
    const { orderId } = req.params;
    if (!mongoose.Types.ObjectId.isValid(orderId)) {
      return res.status(400).json({ message: 'Invalid order ID' });
    }
    const updatedOrder = await Order.findByIdAndUpdate(
      orderId,
      { status: 'received' },
      { new: true, useFindAndModify: false } 
    );

    if (!updatedOrder) {
      return res.status(404).json({ message: 'Order not found' });
    }
    res.status(200).json({ message: 'Order marked as received', order: updatedOrder });
  } catch (error) {
    console.error(`Error marking order as received: ${error.message}`);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.patch('/orders/:orderId/claim', async (req, res) => {
  try {
    const { orderId } = req.params;
    if (!mongoose.Types.ObjectId.isValid(orderId)) {
      return res.status(400).json({ message: 'Invalid order ID' });
    }
    const updatedOrder = await Order.findByIdAndUpdate(
      orderId,
      { status: 'claimed' },
      { new: true }
    );
    if (!updatedOrder) {
      return res.status(404).json({ message: 'Order not found' });
    }
    res.status(200).json({ message: 'Product claimed for order', order: updatedOrder });
  } catch (error) {
    console.error(`Error claiming product: ${error.message}`);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//claimorder

const claimSchema = new mongoose.Schema({
  claimId: { type: String, required: true },
  orderId: { type: String, required: true },
  product: { type: Object, required: true },
  note: { type: String, required: true },
  images: { type: [String], default: [] },
});

const Claim = mongoose.model('Claim', claimSchema);

app.post('/claims', async (req, res) => {
  try {
    const { claimId, orderId, product, note, images } = req.body;
    const newClaim = new Claim({ claimId, orderId, product, note, images });
    await newClaim.save();
    res.status(200).json({ message: 'Claim created successfully', claim: newClaim });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error creating claim', error: error.message });
  }
});

app.get('/claims', async (req, res) => {
  try {
    const claims = await Claim.find(); 
    res.status(200).json(claims); 
  } catch (error) {
    console.error('Error fetching claims:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//cart

const cartSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Customer', required: true },
  quantity: { type: Number, default: 1 },
  price: { type: Number, required: true },
  addedAt: { type: Date, default: Date.now },
  images: { type: String }, 
  brand: { type: String },
  serialNumber: { type: String }
});

const Cart = mongoose.model('Cart', cartSchema);

app.post('/carts', async (req, res) => {
  const { productId, quantity, customerId, price } = req.body;

  if (!productId || !mongoose.Types.ObjectId.isValid(productId)) {
    console.log('Invalid productId:', productId);
    return res.status(400).json({ message: 'ID สินค้าไม่ถูกต้อง' });
  }

  if (!quantity || typeof quantity !== 'number' || quantity < 1) {
    console.log('Invalid quantity:', quantity);
    return res.status(400).json({ message: 'จำนวนสินค้าต้องมากกว่า 0 และเป็นตัวเลข' });
  }

  if (!customerId || !mongoose.Types.ObjectId.isValid(customerId)) {
    console.log('Invalid customerId:', customerId);
    return res.status(400).json({ message: 'ID ผู้ใช้ไม่ถูกต้อง' });
  }

  try {
    const product = await Product.findById(productId);
    if (!product) {
      console.log('Product not found:', productId);
      return res.status(404).json({ message: 'ไม่พบข้อมูลผลิตภัณฑ์' });
    }

    const numericPrice = parseFloat(price.replace(/[^0-9.]/g, ''));
    if (isNaN(numericPrice)) {
      return res.status(400).json({ message: 'ราคาต้องเป็นตัวเลข' });
    }

    const cartItem = await Cart.findOneAndUpdate(
      { productId: new mongoose.Types.ObjectId(productId), customerId: new mongoose.Types.ObjectId(customerId) },
      { 
        $inc: { quantity: quantity }, 
        $set: { 
          addedAt: new Date(), 
          price: numericPrice, 
          brand: product.Brand,  
          serialNumber: product.Serial_number,
          images: product.Images
        } 
      },
      { new: true, upsert: true }
    );

    if (!cartItem) {
      return res.status(500).json({ message: 'ไม่สามารถเพิ่มสินค้าลงตะกร้าได้' });
    }

    console.log('Updated cart item:', cartItem);
    return res.status(200).json({
      message: 'เพิ่มหรืออัปเดตสินค้าลงตะกร้าสำเร็จ',
      cartItem: cartItem
    });
  } catch (error) {
    console.error('Error during cart operation:', error);
    return res.status(500).json({
      message: 'เกิดข้อผิดพลาดในการเพิ่มสินค้าลงตะกร้า',
      error: error.message
    });
  }
});

app.put('/carts/:id', async (req, res) => {
  const { id } = req.params;
  const { quantity } = req.body;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ message: 'ID ตะกร้าไม่ถูกต้อง' });
  }

  if (!quantity || typeof quantity !== 'number' || quantity < 1) {
    return res.status(400).json({ message: 'จำนวนสินค้าต้องมากกว่า 0 และเป็นตัวเลข' });
  }

  try {
    const updatedCartItem = await Cart.findByIdAndUpdate(id, { quantity }, { new: true });
    if (!updatedCartItem) {
      return res.status(404).json({ message: 'ไม่พบรายการตะกร้านี้' });
    }
    res.json({ message: 'อัปเดตจำนวนสินค้าสำเร็จ', cartItem: updatedCartItem });
  } catch (error) {
    console.error('Error updating cart item:', error);
    res.status(500).json({ message: 'อัปเดตจำนวนสินค้าไม่สำเร็จ' });
  }
});

app.delete('/carts/:id', async (req, res) => {
  const { id } = req.params;

  console.log('ID received for deletion:', id);

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ message: 'ID ตะกร้าไม่ถูกต้อง' });
  }

  try {
    const objectId = new mongoose.Types.ObjectId(id);
    console.log('ObjectId for deletion:', objectId);

    const itemToDelete = await Cart.findById(objectId);
    console.log('Item found for deletion:', itemToDelete); 

    if (!itemToDelete) {
      return res.status(404).json({ message: 'ไม่พบรายการสินค้าก่อนการลบ' });
    }

    const result = await Cart.findByIdAndDelete(objectId);
    console.log('Delete result:', result);
    if (result) {
      res.status(200).json({ message: 'ลบสินค้าจากตะกร้าสำเร็จ' });
    } else {
      res.status(404).json({ message: 'ไม่พบสินค้าในตะกร้า' });
    }
  } catch (error) {
    console.error('Error deleting cart item:', error); 
    res.status(500).json({ message: 'ลบสินค้าจากตะกร้าล้มเหลว', error: error.message });
  }
});

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//cartcheckout

const cartsItemSchema = new mongoose.Schema({
  brand: { type: String }, 
  serialNumber: { type: String },
  price: { type: Number, required: true },
  quantity: { type: Number, default: 1 },
});

const cartsItem = mongoose.model('Carts', cartsItemSchema);

app.get('/carts', async (req, res) => {
  try {
    const cartItems = await cartsItem.find();
    res.json(cartItems); 
  } catch (error) {
    res.status(500).send('Error retrieving carts items');
  }
});


//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//โชว์ข้อมูลจังหวัด

const LocationSchema = new mongoose.Schema({
  TambonThai: String,
  DistrictThai: String,
  ProvinceThai: String,
  PostCodeMain: String
});

const ThaiLocation = mongoose.model('locations', LocationSchema);

app.get('/locations', async (req, res) => {
  try {
    const locations = await ThaiLocation.find();

    const uniqueDistrictsSet = new Set(locations.map(item => JSON.stringify({ ProvinceThai: item.ProvinceThai, DistrictThai: item.DistrictThai })));
    const uniqueDistricts = Array.from(uniqueDistrictsSet).map(item => JSON.parse(item));
    
    res.json({
      locations: locations,
      uniqueDistricts: uniqueDistricts 
    });
  } catch (error) {
    console.error('Error fetching locations:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//sell/trades

const tradeSchema = new mongoose.Schema({
  customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Customer', required: true },
  name: { type: String, required: true },
  email: { type: String, required: true, match: [/.+\@.+\..+/, 'Invalid email format'] },
  phone: { type: String, required: true },
  brand: { type: String, required: true },
  year: { type: String, required: true },
  type: { type: String, required: true },
  images: [{ type: String }],
  addedAt: { type: Date, default: Date.now },
});

const Trade = mongoose.model('Trade', tradeSchema);

app.post('/trade', async (req, res) => {
  try {
    const { customerId, name, email, phone, brand, year, type, images, addedAt } = req.body;

    if (!mongoose.Types.ObjectId.isValid(customerId)) {
      return res.status(400).json({ message: 'Invalid customer ID' });
    }

    const newTrade = new Trade({
      customerId: new mongoose.Types.ObjectId(customerId),
      name,
      email,
      phone,
      brand,
      year,
      type,
      images, 
      addedAt,
    });

    await newTrade.save(); 
    res.status(200).json({ message: 'Trade submitted successfully' });
  } catch (error) {
    console.error('Error submitting trade:', error.message);
    res.status(500).json({ message: 'Error submitting trade', error: error.message });
  }
});


app.get('/trade', async (req, res) => {
  try {
    const trades = await Trade.find();  
    res.status(200).json(trades);  
  } catch (error) {
    res.status(500).json({ message: 'Error retrieving trades', error: error.message });
  }
});


//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
