const express = require ("express");
const app = express();
const { pool } = require ("./dbConfig");
const bcrypt = require ("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
require("dotenv").config();

const PORT = process.env.PORT || 5000;

const initializePassport = require("./passportConfig");

initializePassport(passport);

// Middleware


app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false,
    
  })
  );
// Funtion inside passport which initializes passport
app.use(passport.initialize());
// Store our variables to be persisted across the whole session. Works with app.use(Session) above
app.use(passport.session());
app.use(flash());



app.use(express.static('./public'));
app.set('views', './public/views');
app.use(express.urlencoded({ extended: false }));
app.set("view engine", "ejs");


app.get("/", (req, res) => {
    res.render("index");
});

app.get("/register", checkAuthenticated, (req, res) =>{
 res.render("register.ejs");
});
app.get("/login", checkAuthenticated, (req, res) =>{
    res.render("login.ejs");
});
app.get("/dashboard", checkNotAuthenticated, (req, res) =>{
    res.render("dashboard", { user: req.user.nome});
});
app.get("/logout", (req, res) => {
    req.logout();
    req.flash("success_msg", "Você foi desconectado!")
    res.redirect("/login");
  });

app.post('/register', async (req, res) => {
    let{ name, email, password, password2} = req.body;
    // console.log({
    //     name,
    //     email,
    //     password,
    //     password2
    // });
  
    let errors = [];
    

    if(!name || !email || !password || !password2){
        errors.push({ message:"Por favor preencha todos os campos!"});
    }
    
    if(password.length < 6){
        errors.push({ message:"A senha precisa ter pelo menos 6 caracteres!"}); 
    }
    if(password != password2){
        errors.push({ message:"As senhas não conferem"}); 
    }
    if(errors.length > 0){
        res.render("register", { errors });
    }else{
        //Validação de formulário ok
        let hashedPassword = await bcrypt.hash(password, 10);
        // console.log(hashedPassword);

        pool.query(
            `SELECT * FROM usuario
              WHERE email = $1`,
            [email],
            (err, results) => {
              if (err) {
                // console.log(err);
              }
            //   console.log(results.rows);
      
              if (results.rows.length > 0) {
                errors.push({ message:"Email já cadastrado!"});
                res.render("register", { errors });
                
              } else {
                pool.query(
                    `INSERT INTO usuario (nome, email, password)
                    VALUES ($1, $2, $3)
                    RETURNING id, password`,
                    [name, email, hashedPassword],
                    (err, results) => {
                        if(err){
                            throw err
                        }
                        // console.log(results.rows);
                        
                        req.flash("success_msg", "You are now registered. Please log in");
                        res.redirect("/login");

                        }
                    );
                }
            }
        )
    }
});

app.post(
    "/login", 
    passport.authenticate("local",{
        successRedirect: "/dashboard",
        failureRedirect: "/login",
        failureFlash: true
    })
);

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return res.redirect("/dashboard");
    }
    next();
  }
  
  function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    res.redirect("/login");
  }
// app.listen(PORT, () => {
//     // console.log(`Server on na port ${PORT}`);
// })