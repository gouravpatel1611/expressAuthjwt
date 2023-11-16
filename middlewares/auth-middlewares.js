import jwt from 'jsonwebtoken';
import UserModel from '../models/User.js';


const checkUserAuth = async (req,res,next)=>{
    let token
    // Get token from header 
    const {authorization} = req.headers;

    if(authorization && authorization.startsWith('Bearer')){
        try{
            token = authorization.split(' ')[1];
            //verify token
            const {userId} = jwt.verify(token, process.env.JWT_SECRET_KEY);
            // Get user from token
            req.user = await UserModel.findById(userId,'-password');
            next();
        }catch(err){
            console.log(err);
            res.status(401).send({"status":"failed","message":"Unauthorized User"});
        }  
    }
    if(!token){
        res.status(401).send({"status":"failed","message":"Unauthorized User, No Token"});
    }
}


export default checkUserAuth;