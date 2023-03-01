import express from 'express';
import cors from 'cors';
import {MongoClient} from 'mongodb';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import fs from 'fs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

/**
 * CONFIG STUFF
 */

dotenv.config();

const config = {
    PORT: parseInt((process.env.PORT || 3000).toString().trim()),
    ALLOWED_ORIGINS: (process.env.ALLOWED_ORIGINS || '*').toString().trim().split(/[\s,]+/),
    MONGODB_CONNECTION_STRING: (process.env.MONGODB_CONNECTION_STRING || 'mongodb://127.0.0.1').toString().trim(),
    TOKEN_LIFETIME: (process.env.TOKEN_LIFETIME || '7d').toString().trim()
};

/**
 * JWT STUFF
 */

let privkey;
let pubkey;

const createKeyPairIfNotExists = () => {
    if (!(fs.existsSync('./privkey.pem') && fs.existsSync('./pubkey.pem'))) {
        const keypair = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
        fs.writeFileSync('./privkey.pem', keypair.privateKey);
        fs.writeFileSync('./pubkey.pem', keypair.publicKey);
    }
    privkey = fs.readFileSync('./privkey.pem');
    pubkey = fs.readFileSync('./pubkey.pem');
};
createKeyPairIfNotExists();

const createToken = async (payload) => {
    return new Promise((resolve, _) => {
        jwt.sign(payload, privkey, {
            algorithm: 'RS256',
            expiresIn: config.TOKEN_LIFETIME,
            header: { jwk: pubkey }
        }, (err, token) => resolve(err ? undefined : token));
    });
};

const verifyToken = async (token) => {
    return new Promise((resolve, _) => {
        jwt.verify(token, pubkey, {
            algorithms: ['RS256', 'HS256']
        }, (err, decoded) => resolve(err ? undefined : decoded));
    });
};

/**
 * MONGODB STUFF
 */

const mongoClient = new MongoClient(config.MONGODB_CONNECTION_STRING);

let conn;
try {
    conn = await mongoClient.connect();
} catch (e) {
    console.error(e);
    process.exit(1);
}

let db = conn.db('example');

/**
 * EXPRESS SETUP
 */

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: config.ALLOWED_ORIGINS }));
app.use(cookieParser());

/**
 * AUTH MIDDLEWARE
 */

const authRequired = async (req, res, next) => {
    const token = req.cookies['auth_token'];
    if (token) {
        const payload = await verifyToken(token);
        if (payload) {
            let users = await db.collection('users');
            req.user = await users.findOne({'_id': payload.userId})
            if (req.user) {
                return next();
            }
        }
    }
    return res.status(401).send({
        error: 'Unauthorized'
    });
};

/**
 * EXPRESS ROUTES
 */

app.get('/', async (req, res) => {
    return res.send({
        message: 'OK'
    });
});

app.get('/me', authRequired, async (req, res) => {
    return res.send({
        id: req.user.id,
        username: req.user.username
    });
});

app.post('/login', async (req, res) => {
    let {username, password} = req.body;
    let users = await db.collection('users');
    const user = await users.findOne({username});
    if (user) {
        if (await bcrypt.compare(password, user.password)) {
            const token = await createToken({
                userId: user.id
            });
            res.cookie('auth_token', token);
            return res.send({
                message: 'Login Success'
            });
        }
    }
    return res.status(401).send({
        error: 'Invalid Credentials'
    });
});

/**
 * START EXPRESS SERVER
 */

app.listen(config.PORT, () => console.log(`Server listening on port ${config.PORT}...`));