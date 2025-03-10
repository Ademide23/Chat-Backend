const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const io = require('socket.io')(8080, {
    cors: {
        origin: 'http://localhost:3002',
    }
});

// Connect DB
require('./db/connection');

// Import Files
const Users = require('./models/Users');
const Conversations = require('./models/Conversations');
const Messages = require('./models/Messages');

// app Use
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors());

const port = process.env.PORT || 8000;

// Socket.io
let users = [];
io.on('connection', socket => {
    console.log('User connected', socket.id);
    socket.on('addUser', userId => {
        const isUserExist = users.find(user => user.userId === userId);
        if (!isUserExist) {
            const user = { userId, socketId: socket.id };
            users.push(user);
            io.emit('getUsers', users);
        }
    });

    socket.on('sendMessage', async ({ senderId, receiverId, message, conversationId }) => {
        const receiver = users.find(user => user.userId === receiverId);
        const sender = users.find(user => user.userId === senderId);
        const user = await Users.findById(senderId);
        console.log('sender :>> ', sender, receiver);
        if (receiver) {
            io.to(receiver.socketId).to(sender.socketId).emit('getMessage', {
                senderId,
                message,
                conversationId,
                receiverId,
                user: { id: user._id, fullName: user.fullName, email: user.email }
            });
            }else {
                io.to(sender.socketId).emit('getMessage', {
                    senderId,
                    message,
                    conversationId,
                    receiverId,
                    user: { id: user._id, fullName: user.fullName, email: user.email }
                });
            }
        });

    socket.on('disconnect', () => {
        users = users.filter(user => user.socketId !== socket.id);
        io.emit('getUsers', users);
    });

    // Add logout handler
    socket.on('logout', (userId) => {
        users = users.filter(user => user.userId !== userId);
        io.emit('getUsers', users);
    });
});

// Routes
app.get('/', (req, res) => {
    res.send('Welcome');
})

app.post('/api/register', async (req, res) => {
    try {
        const { fullName, email, password } = req.body;
        console.log(fullName, email, password);
        
        if (!fullName || !email || !password) {
            return res.status(400).send('Please fill all required fields');
        }
        
        const isAlreadyExist = await Users.findOne({ email });
        if (isAlreadyExist) {
            return res.status(400).send('User already exists');
        }
        
        const newUser = new Users({ fullName, email });
        const hashedPassword = await bcryptjs.hash(password, 10);
        newUser.password = hashedPassword;
        await newUser.save();
        
        return res.status(200).send('User registered successfully');
    } catch (error) {
        console.log(error, 'Error');
        return res.status(500).send('Internal server error');
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Please fill all required fields' });
        }
        
        const user = await Users.findOne({ email });
        if (!user) {
            return res.status(400).json({ success: false, message: 'User email or password is incorrect' });
        }
        
        const validateUser = await bcryptjs.compare(password, user.password);
        if (!validateUser) {
            return res.status(400).json({ success: false, message: 'User email or password is incorrect' });
        }
        
        const payload = {
            userId: user._id,
            email: user.email
        }
        const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY || 'THIS_IS_A_JWT_SECRET_KEY';

        jwt.sign(payload, JWT_SECRET_KEY, { expiresIn: 84600 }, async (err, token) => {
            if (err) return handleError(res, err, 'Error generating token');
            
            try {
                await Users.updateOne({ _id: user._id }, { $set: { token } });
                return res.status(200).json({ 
                    success: true, 
                    user: { id: user._id, email: user.email, fullName: user.fullName }, 
                    token 
                });
            } catch (updateError) {
                return handleError(res, updateError, 'Error updating user token');
            }
        });
    } catch (error) {
        return handleError(res, error);
    }
});

app.post('/api/conversation', async (req, res) => {
    try {
        const { senderId, receiverId } = req.body;
        
        if (!senderId || !receiverId) {
            return res.status(400).json({ success: false, message: 'Both senderId and receiverId are required' });
        }
        
        const newConversation = new Conversations({ members: [senderId, receiverId] });
        await newConversation.save();
        res.status(200).json({ success: true, message: 'Conversation created successfully' });
    } catch (error) {
        return handleError(res, error, 'Error creating conversation');
    }
});

app.get('/api/conversations/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        const conversations = await Conversations.find({ members: { $in: [userId] } });
        const conversationUserData = Promise.all(conversations.map(async (conversation) => {
            const receiverId = conversation.members.find((member) => member !== userId);
            const user = await Users.findById(receiverId);
            return { user: { receiverId: user._id, email: user.email, fullName: user.fullName }, conversationId: conversation._id }
        }))
        res.status(200).json(await conversationUserData);
    } catch (error) {
        console.log(error, 'Error')
    }
})

app.post('/api/message', async (req, res) => {
    try {
        const { conversationId, senderId, message, receiverId = '' } = req.body;
        
        if (!senderId || !message) {
            return res.status(400).json({ success: false, message: 'Please fill all required fields' });
        }
        
        if (conversationId === 'new' && receiverId) {
            try {
                const newConversation = new Conversations({ members: [senderId, receiverId] });
                await newConversation.save();
                const newMessage = new Messages({ conversationId: newConversation._id, senderId, message });
                await newMessage.save();
                return res.status(200).json({ success: true, message: 'Message sent successfully' });
            } catch (innerError) {
                return handleError(res, innerError, 'Error creating new conversation and message');
            }
        } else if (!conversationId && !receiverId) {
            return res.status(400).json({ success: false, message: 'Please fill all required fields' });
        }
        
        const newMessage = new Messages({ conversationId, senderId, message });
        await newMessage.save();
        res.status(200).json({ success: true, message: 'Message sent successfully' });
    } catch (error) {
        return handleError(res, error, 'Error sending message');
    }
});

app.get('/api/message/:conversationId', async (req, res) => {
    try {
        const checkMessages = async (conversationId) => {
            console.log(conversationId, 'conversationId')
            const messages = await Messages.find({ conversationId });
            const messageUserData = Promise.all(messages.map(async (message) => {
                const user = await Users.findById(message.senderId);
                return { user: { id: user._id, email: user.email, fullName: user.fullName }, message: message.message }
            }));
            res.status(200).json(await messageUserData);
        }
        const conversationId = req.params.conversationId;
        if (conversationId === 'new') {
            const checkConversation = await Conversations.find({ members: { $all: [req.query.senderId, req.query.receiverId] } });
            if (checkConversation.length > 0) {
                checkMessages(checkConversation[0]._id);
            } else {
                return res.status(200).json([])
            }
        } else {
            checkMessages(conversationId);
        }
    } catch (error) {
        console.log('Error', error)
    }
})

app.get('/api/users/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        const users = await Users.find({ _id: { $ne: userId } });
        const usersData = Promise.all(users.map(async (user) => {
            return { user: { email: user.email, fullName: user.fullName, receiverId: user._id } }
        }))
        res.status(200).json(await usersData);
    } catch (error) {
        console.log('Error', error)
    }
})

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ success: false, message: 'Access denied. No token provided.' });
    }
    
    try {
        const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY || 'THIS_IS_A_JWT_SECRET_KEY';
        const decoded = jwt.verify(token, JWT_SECRET_KEY);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Invalid token' });
    }
};

// Get user profile
app.get('/api/profile/:userId', verifyToken, async (req, res) => {
    try {
        const userId = req.params.userId;
        
        // Check if the requesting user has permission to view this profile
        if (req.user.userId !== userId) {
            return res.status(403).json({ success: false, message: 'Access denied' });
        }
        
        const user = await Users.findById(userId).select('-password');
        
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        return res.status(200).json({ success: true, user });
    } catch (error) {
        return handleError(res, error, 'Error fetching user profile');
    }
});

// Edit user profile
app.put('/api/profile/:userId', verifyToken, async (req, res) => {
    try {
        const userId = req.params.userId;
        
        // Check if the requesting user has permission to edit this profile
        if (req.user.userId !== userId) {
            return res.status(403).json({ success: false, message: 'Access denied' });
        }
        
        const { fullName, email, bio, profilePicture, currentPassword, newPassword } = req.body;
        
        // Find the user
        const user = await Users.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        // Prepare update object
        const updateData = {};
        
        // Update basic info if provided
        if (fullName) updateData.fullName = fullName;
        if (bio) updateData.bio = bio;
        if (profilePicture) updateData.profilePicture = profilePicture;
        
        // Handle email change (requires validation)
        if (email && email !== user.email) {
            const emailExists = await Users.findOne({ email });
            if (emailExists) {
                return res.status(400).json({ success: false, message: 'Email already in use' });
            }
            updateData.email = email;
        }
        
        // Handle password change
        if (currentPassword && newPassword) {
            const isPasswordValid = await bcryptjs.compare(currentPassword, user.password);
            if (!isPasswordValid) {
                return res.status(400).json({ success: false, message: 'Current password is incorrect' });
            }
            
            // Hash the new password
            updateData.password = await bcryptjs.hash(newPassword, 10);
        }
        
        // Update the user
        const updatedUser = await Users.findByIdAndUpdate(
            userId,
            { $set: updateData },
            { new: true }
        ).select('-password');
        
        return res.status(200).json({ 
            success: true, 
            message: 'Profile updated successfully',
            user: updatedUser
        });
    } catch (error) {
        return handleError(res, error, 'Error updating user profile');
    }
});

// Add logout route
app.post('/api/logout', verifyToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        
        // Remove token from user document
        await Users.findByIdAndUpdate(userId, {
            $set: { token: null }
        });
        
        // Remove user from active socket users
        users = users.filter(user => user.userId !== userId);
        io.emit('getUsers', users);
        
        return res.status(200).json({
            success: true,
            message: 'Logged out successfully'
        });
    } catch (error) {
        return handleError(res, error, 'Error during logout');
    }
});

app.listen(port, () => {
    console.log('listening on port ' + port);
})