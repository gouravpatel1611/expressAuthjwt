import UserModel from '../models/User.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';




class UserController{
    // User Ragistration 
    static userRegistration = async (req,res)=>{
        const {name,email,password, password_confirmation, tc} = req.body;
        const user = await UserModel.findOne({email:email});
        if(user){
            res.send({"status":"failed", "message":"Email already exists"});
        }else{
            if(name && email && password && password_confirmation && tc){
                if(password === password_confirmation){
                    try{
                        const salt = await bcrypt.genSalt(10);
                        const hashPassword = await bcrypt.hash(password,salt);
                        const doc = new UserModel({
                            name:name,
                            email:email,
                            password:hashPassword,
                            tc:tc
                        })
                        const saved_user = await doc.save();
                        // const saved_user = await UserModel.findOne({email:email},'email');
                        //Generate JWT Token
                        const token = jwt.sign({userId:saved_user._id},process.env.JWT_SECRET_KEY,{expiresIn:'1d'})
                        res.status(201).send({"status":"Success", "message":"User Ragistered Successfull !","token":token});
                    }catch(err){
                        console.log(err);
                        res.send({"status":"failed", "message":"Unable to Ragister"});
                    }
                }else{
                    res.send({"status":"failed", "message":"Password and Confirm Password doesn't match"});
                }
            }else{
                res.send({"status":"failed", "message":"All fields are required"});
            }
        }
    }

    // User Login
    static userLogin = async (req,res)=>{
        try{
            const {email, password} = req.body;
            if(email && password){
                const user = await UserModel.findOne({email:email});
                if(user != null){
                    const isMatch = await bcrypt.compare(password,user.password);
                    if(isMatch && (email === user.email)){
                        const token = jwt.sign({userId:user._id},process.env.JWT_SECRET_KEY,{expiresIn:"1d"});
                        res.send({"status":"success", "message":" User Login Successfully !",token});
                    }else{
                        res.send({"status":"failed", "message":"Email OR Password is not Valid"});
                    }
                }else{
                    res.send({"status":"failed", "message":"You are Not a Registered User"});
                }
            }else{
                res.send({"status":"failed", "message":"All fields are required"});
            }
        }catch(err){
            console.log(err);
            res.send({"status":"failed", "message":"Unable to Login"});
            
        }
    }
}


export default UserController;