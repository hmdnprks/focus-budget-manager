const mongoose = require('mongoose'),
    bcrypt = require('bcrypt');

const Schema = mongoose.Schema({
    username : {
        type : String,
        unique : true,
        required : true
    },
    password : {
        type : String,
        required : true
    },

    clients : [{}]
});


// generate salt and hash for our passwords
Schema.pre('save', function(next){
    const user = this;

    if(this.isModified('password') || this.isNew){
        bcrypt.genSalt(10, (error, salt) => {
            if(error) return next(error);

            bcrypt.hash(user.password, salt, (error, hash) => {
                if(error) return next(error);

                user.password = hash;
                next();
            });
        });
    } else {
        return next();
    }
});

// compare passwords to check if the login attempt is valid or not
Schema.methods.comparePassword = function(password, callback){
    bcrypt.compare(password, this.password, (error, matches) => {
        if(error) return callback(error);
        callback(null, matches);
    });
};

// create user model
mongoose.model('User', Schema);