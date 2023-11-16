import mongoose  from "mongoose";


const connectDB = async (url)=>{
    try{
        const DB_OPTIONS ={
            dbName : "expressAuthJwt"
        }
        const db = await mongoose.connect(url,DB_OPTIONS);
        console.log("Connected Successfully....!");
    }catch(err){
        console.log(err);
    }
}


export default connectDB;