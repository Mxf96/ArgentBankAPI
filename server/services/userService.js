const User = require("../database/models/userModel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// === Créer un utilisateur ===
module.exports.createUser = async (serviceData) => {
  try {
    const user = await User.findOne({ email: serviceData.email });
    if (user) {
      throw new Error("Email already exists");
    }

    const hashPassword = await bcrypt.hash(serviceData.password, 12);

    const newUser = new User({
      email: serviceData.email,
      password: hashPassword,
      firstName: serviceData.firstName,
      lastName: serviceData.lastName,
    });

    let result = await newUser.save();
    return result;
  } catch (error) {
    console.error("Error in userService.js", error);
    throw new Error(error.message);
  }
};

// === Connexion utilisateur ===
module.exports.loginUser = async (serviceData) => {
  try {
    const user = await User.findOne({ email: serviceData.email });
    if (!user) throw new Error("User not found!");

    const isValid = await bcrypt.compare(serviceData.password, user.password);
    if (!isValid) throw new Error("Password is invalid");

    // ✅ Crée un token sécurisé avec l'ID du user
    const token = jwt.sign(
      { userId: user._id },
      process.env.SECRET_KEY || "default-secret-key",
      { expiresIn: "1d" }
    );

    return { token };
  } catch (error) {
    console.error("Error in userService.js", error);
    throw new Error(error.message);
  }
};

// === Récupérer le profil utilisateur ===
module.exports.getUserProfile = async (serviceData) => {
  try {
    const authHeader = serviceData.headers.authorization;
    if (!authHeader) throw new Error("No authorization header");

    const token = authHeader.split(" ")[1];
    if (!token) throw new Error("Invalid token format");

    // ✅ Vérifie et décode le token
    const decoded = jwt.verify(
      token,
      process.env.SECRET_KEY || "default-secret-key"
    );
    const userId = decoded.userId;

    const user = await User.findById(userId);
    if (!user) throw new Error("User not found!");

    return {
      id: user._id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
    };
  } catch (error) {
    console.error("Error in userService.getUserProfile:", error);
    throw new Error(error.message);
  }
};

// === Mettre à jour le profil utilisateur ===
module.exports.updateUserProfile = async (serviceData) => {
  try {
    const authHeader = serviceData.headers.authorization;
    if (!authHeader) throw new Error("No authorization header");

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(
      token,
      process.env.SECRET_KEY || "default-secret-key"
    );
    const userId = decoded.userId;

    const user = await User.findByIdAndUpdate(
      userId,
      {
        firstName: serviceData.body.firstName,
        lastName: serviceData.body.lastName,
      },
      { new: true }
    );

    if (!user) throw new Error("User not found!");

    return {
      id: user._id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
    };
  } catch (error) {
    console.error("Error in userService.updateUserProfile:", error);
    throw new Error(error.message);
  }
};
