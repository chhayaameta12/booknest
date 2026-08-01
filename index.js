import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import multer from "multer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { v2 as cloudinary } from "cloudinary";
import { CloudinaryStorage } from "multer-storage-cloudinary";


dotenv.config({ override: true });

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const saltRounds = 10;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const uploadDir = path.join(__dirname, "public", "images", "uploads");

if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "booknest",
    allowed_formats: ["jpg", "jpeg", "png", "webp"],
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
});

const app = express();
const port = 3000;

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: "booknest-secret",
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

const publicRoutes = ["/", "/start", "/login", "/register", "/logout", "/auth/google", "/auth/google/callback"];
app.use((req, res, next) => {
    const pathname = req.path;
    const isPublicRoute = publicRoutes.includes(pathname)
        || pathname.startsWith("/css/")
        || pathname.startsWith("/js/")
        || pathname.startsWith("/images/");

    if (req.isAuthenticated() || isPublicRoute) {
        return next();
    }

    req.session.returnTo = req.originalUrl;
    return res.redirect("/start");
});

app.set("view engine", "ejs");



const dbConfig = {
  connectionString: process.env.DATABASE_URL,
};

if (process.env.DATABASE_URL && !process.env.DATABASE_URL.includes("localhost") && !process.env.DATABASE_URL.includes("127.0.0.1")) {
  dbConfig.ssl = { rejectUnauthorized: false };
}

const db = new pg.Client(dbConfig);

if (process.env.DATABASE_URL) {
    db.connect()
        .then(async () => {
            console.log("✅ Connected to PostgreSQL");
            await ensureAuthColumns();
        })
        .catch(err => console.error("❌ Database connection failed:", err));
} else {
    console.warn("⚠️ DATABASE_URL is not set. Add it to your .env file to enable database features.");
}

async function ensureAuthColumns() {
    try {
        await db.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id VARCHAR(255)");
        await db.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS provider VARCHAR(50) DEFAULT 'local'");
    } catch (err) {
        console.warn("⚠️ Could not ensure auth columns:", err.message);
    }
}

passport.use(new LocalStrategy(
    {
        usernameField: "email",
        passwordField: "password"
    },

    async function(email, password, done) {

        try {

            const result = await db.query(
                "SELECT * FROM users WHERE email=$1",
                [email]
            );

            if(result.rows.length === 0){

                return done(null,false,{
                    message:"User not found"
                });

            }

            const user = result.rows[0];

            if (!user.password) {
                return done(null, false, {
                    message: "Please sign in with Google"
                });
            }

            const match = await bcrypt.compare(
                password,
                user.password
            );

            if(!match){

                return done(null,false,{
                    message:"Incorrect Password"
                });

            }

            return done(null,user);

        }

        catch(err){

            return done(err);

        }

    }

));

const googleClientId = process.env.GOOGLE_CLIENT_ID;
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;
const googleCallbackUrl = process.env.GOOGLE_CALLBACK_URL || "http://localhost:3000/auth/google/callback";

if (googleClientId && googleClientSecret) {
    passport.use(new GoogleStrategy(
        {
            clientID: googleClientId,
            clientSecret: googleClientSecret,
            callbackURL: googleCallbackUrl,
            scope: ["profile", "email"]
        },
        async function(accessToken, refreshToken, profile, done) {
            try {
                const email = profile.emails?.[0]?.value;
                const googleId = profile.id;
                const displayName = profile.displayName || profile.name?.givenName || email?.split("@")[0] || "Google User";
                const profilePicture = profile.photos?.[0]?.value || null;

                if (!email) {
                    return done(null, false, { message: "No email provided by Google" });
                }

                const existingUser = await db.query(
                    "SELECT * FROM users WHERE email=$1",
                    [email]
                );

                if (existingUser.rows.length > 0) {
                    const user = existingUser.rows[0];

                    if (!user.google_id) {
                        await db.query(
                            "UPDATE users SET google_id=$1, provider='google', profile_picture=COALESCE($2, profile_picture) WHERE id=$3",
                            [googleId, profilePicture, user.id]
                        );
                    }

                    return done(null, { ...user, google_id: user.google_id || googleId });
                }

                const result = await db.query(
                    `INSERT INTO users (name, email, password, profile_picture, google_id, provider)
                     VALUES ($1, $2, $3, $4, $5, 'google')
                     RETURNING *`,
                    [displayName, email, null, profilePicture, googleId]
                );

                return done(null, result.rows[0]);
            } catch (err) {
                return done(err);
            }
        }
    ));
} else {
    console.warn("⚠️ Google OAuth is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your environment.");
}
passport.serializeUser((user,done)=>{

    done(null,user.id);

});

passport.deserializeUser(async(id,done)=>{

    try{

        const result = await db.query(
            "SELECT * FROM users WHERE id=$1",
            [id]
        );

        done(null,result.rows[0]);

    }

    catch(err){

        done(err);

    }

}); 

app.get("/", (req, res) => {
    res.render("index");
});



app.get("/start", (req, res) => {
    res.render("start");
});

app.get("/add-shelf", isAuthenticated, (req, res) => {
    res.render("addShelf");
});
app.post("/add-shelf", isAuthenticated, upload.single("image"), async (req, res) => {

    const { name } = req.body;
    const image = req.file
    ? req.file.path
    : (req.body.image_url || null);

    await db.query(
        "INSERT INTO shelves(name, image_url) VALUES($1, $2)",
        [name, image]
    );

    res.redirect("/genres");

});
app.get("/genres", isAuthenticated, async (req, res) => {

    const result = await db.query(
        "SELECT * FROM shelves ORDER BY id"
    );

    res.render("genres", {
        shelves: result.rows
    });

});
app.get("/shelf/:id", isAuthenticated, async (req, res) => {

    const shelfId = req.params.id;

    const shelf = await db.query(
        "SELECT * FROM shelves WHERE id=$1",
        [shelfId]
    );

    const books = await db.query(
        "SELECT * FROM books WHERE shelf_id=$1 ORDER BY created_at DESC",
        [shelfId]
    );

    res.render("shelf", {
        shelf: shelf.rows[0],
        books: books.rows
    });

});
app.get("/add-book/:id", isAuthenticated, async (req, res) => {

    const shelf = await db.query(
        "SELECT * FROM shelves WHERE id=$1",
        [req.params.id]
    );

    res.render("addBook", {
        shelf: shelf.rows[0]
    });

});



app.post("/add-book/:id", isAuthenticated, upload.single("cover_image"), async (req, res) => {

    const shelfId = req.params.id;

    const {
        title,
        author,
        cover_url,
        status,
        rating,
        started_date,
        finished_date,
        review,
        quote,
        favorite
    } = req.body;

    const startedDate = started_date || null;
    const finishedDate = finished_date || null;
    const bookRating = rating || null;
    const coverImage = req.file
    ? req.file.path
    : (cover_url || null);

    await db.query(
        `INSERT INTO books
        (
            shelf_id,
            title,
            author,
            cover_url,
            status,
            rating,
            review,
            quote,
            started_date,
            finished_date,
            favorite
        )
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [
            shelfId,
            title,
            author,
            coverImage,
            status,
            bookRating,
            review,
            quote,
            startedDate,
            finishedDate,
            favorite ? true : false
        ]
    );
    res.redirect("/shelf/" + shelfId);

});
app.get("/book/:id", isAuthenticated, async (req, res) => {

    const result = await db.query(
        "SELECT * FROM books WHERE id=$1",
        [req.params.id]
    );

    res.render("bookDetails", {
        book: result.rows[0]
    });

});

app.post("/delete-book/:id", isAuthenticated, async (req, res) => {

    const bookId = req.params.id;

    // Find the shelf before deleting
    const result = await db.query(
        "SELECT shelf_id FROM books WHERE id=$1",
        [bookId]
    );

    const shelfId = result.rows[0].shelf_id;

    // Delete the book
    await db.query(
        "DELETE FROM books WHERE id=$1",
        [bookId]
    );

    res.redirect("/shelf/" + shelfId);

});
app.get("/edit-book/:id", isAuthenticated, async (req, res) => {

    const result = await db.query(
        "SELECT * FROM books WHERE id=$1",
        [req.params.id]
    );

    res.render("editBook", {

        book: result.rows[0]

    });

});

app.get("/login", (req, res) => {
    res.render("login");
});

app.post(
    "/login",
    passport.authenticate("local", {
        failureRedirect: "/login"
    }),
    (req, res) => {
        const returnTo = req.session.returnTo || "/dashboard";
        delete req.session.returnTo;
        res.redirect(returnTo);
    }
);

app.get("/auth/google", (req, res, next) => {
    if (!googleClientId || !googleClientSecret) {
        return res.status(500).send("Google OAuth is not configured yet. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to your .env file.");
    }
    next();
}, passport.authenticate("google", {
    scope: ["profile", "email"],
    callbackURL: googleCallbackUrl
}));

app.get(
    "/auth/google/callback",
    (req, res, next) => {
        if (!googleClientId || !googleClientSecret) {
            return res.status(500).send("Google OAuth is not configured yet. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to your .env file.");
        }
        next();
    },
    passport.authenticate("google", {
        failureRedirect: "/login",
        callbackURL: googleCallbackUrl
    }),
    (req, res) => {
        const returnTo = req.session.returnTo || "/dashboard";
        delete req.session.returnTo;
        res.redirect(returnTo);
    }
);

app.get("/register", (req, res) => {
    res.render("register");
});
app.post("/register", upload.single("profile_picture"), async (req, res) => {

    const { name, email, password } = req.body;
    const profilePicture = req.file
    ? req.file.path
    : (req.body.profile_picture_url || req.body.profile_picture || null);

    try {

        // Check if email already exists
        const existingUser = await db.query(
            "SELECT * FROM users WHERE email = $1",
            [email]
        );

        if (existingUser.rows.length > 0) {

            return res.send("Email already registered.");

        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(
            password,
            saltRounds
        );

        // Save user
        await db.query(

            `INSERT INTO users
            (name, email, password, profile_picture)
            VALUES ($1, $2, $3, $4)`,

            [
                name,
                email,
                hashedPassword,
                profilePicture
            ]

        );

        res.redirect("/login");

    } catch (err) {

        console.log(err);

        res.send("Something went wrong.");

    }

});

app.get("/dashboard", isAuthenticated, async (req, res) => {
    try {
        const booksResult = await db.query(
            "SELECT * FROM books ORDER BY created_at DESC"
        );
        const books = booksResult.rows;

        const currentlyReading = books.filter((book) => book.status === "currently reading").length;
        const completed = books.filter((book) => book.status === "completed").length;
        const wantToRead = books.filter((book) => book.status === "want to read").length;
        const favorites = books.filter((book) => book.favorite === true).length;

        res.render("dashboard", {
            user: req.user,
            books,
            currentlyReading,
            completed,
            wantToRead,
            favorites
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Unable to load dashboard.");
    }
});

app.get("/profile", isAuthenticated, async (req, res) => {
    try {
        const userResult = await db.query(
            "SELECT * FROM users WHERE id=$1",
            [req.user.id]
        );

        const shelfCountResult = await db.query("SELECT COUNT(*)::int AS count FROM shelves");
        const bookCountResult = await db.query("SELECT COUNT(*)::int AS count FROM books");
        const ratingResult = await db.query(
            "SELECT COALESCE(AVG(rating), 0)::float AS average_rating FROM books WHERE rating IS NOT NULL"
        );
        const highlightBooksResult = await db.query(
            "SELECT * FROM books WHERE favorite=true OR review IS NOT NULL ORDER BY created_at DESC LIMIT 4"
        );

        res.render("profile", {
            user: userResult.rows[0],
            shelfCount: shelfCountResult.rows[0].count,
            bookCount: bookCountResult.rows[0].count,
            averageRating: Number(ratingResult.rows[0].average_rating).toFixed(1),
            highlightBooks: highlightBooksResult.rows
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Unable to load profile.");
    }
});

app.post("/profile/update-photo", isAuthenticated, upload.single("profile_picture"), async (req, res) => {
    const profilePicture = req.file
        ? req.file.path
        : (req.body.profile_picture_url || req.body.profile_picture || null);

    try {
        await db.query(
            "UPDATE users SET profile_picture=$1 WHERE id=$2",
            [profilePicture, req.user.id]
        );

        res.redirect("/profile");
    } catch (err) {
        console.error(err);
        res.status(500).send("Unable to update profile picture.");
    }
});

app.use((req, res, next) => {
    if (req.path === "/") {
        return res.render("index");
    }
    return res.redirect("/start");
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }

    res.redirect("/login");
}

app.get("/logout", (req, res) => {
    req.logout(function (err) {
        if (err) {
            return res.status(500).send("Logout failed.");
        }

        res.redirect("/");
    });
});