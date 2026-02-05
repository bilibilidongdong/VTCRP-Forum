const express = require('express');
const session = require('express-session');
const svgCaptcha = require('svg-captcha');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const multer = require('multer');

// ===================== 基础配置 =====================
const app = express();
const PORT = 3000;

// 数据文件路径
const USER_DATA_PATH = path.resolve(__dirname, 'data', 'users.json');
const POST_DATA_PATH = path.resolve(__dirname, 'data', 'posts.json');

// 头像上传配置
const avatarStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const avatarDir = path.resolve(__dirname, 'public', 'assets', 'avatars');
    if (!fs.existsSync(avatarDir)) fs.mkdirSync(avatarDir, { recursive: true });
    cb(null, avatarDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext)) {
      return cb(new Error('仅支持jpg/jpeg/png/gif/webp格式的头像！'));
    }
    const filename = `${req.session.user.id}_${Date.now()}${ext}`;
    cb(null, filename);
  }
});
const upload = multer({ storage: avatarStorage, limits: { fileSize: 5 * 1024 * 1024 } });

// ===================== 核心中间件 =====================
app.use(session({
  secret: 'VTCRP_Forum_2026_Secret_Key',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000, httpOnly: true }
}));

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.resolve(__dirname, 'public')));

// ===================== 数据初始化 =====================
const initUserData = () => {
  try {
    const dataDir = path.dirname(USER_DATA_PATH);
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    if (!fs.existsSync(USER_DATA_PATH)) {
      const officialPassword = bcrypt.hashSync("VTCRP_Official_2026", 10);
      const defaultUsers = [
        {
          id: 1,
          username: "VTCRP Official",
          password: officialPassword,
          avatar: "",
          isVerified: true,
          isAdmin: true,
          tags: ["官方", "VTCRP", "Roleplay", "TangCounty"],
          createdAt: new Date().toISOString()
        }
      ];
      fs.writeFileSync(USER_DATA_PATH, JSON.stringify(defaultUsers, null, 2), 'utf8');
      console.log("✅ 用户数据文件初始化成功，已创建官方账号");
    }
  } catch (err) {
    console.error("❌ 用户数据初始化失败：", err.message);
  }
};

const initPostData = () => {
  try {
    const dataDir = path.dirname(POST_DATA_PATH);
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    if (!fs.existsSync(POST_DATA_PATH)) {
      fs.writeFileSync(POST_DATA_PATH, JSON.stringify([], null, 2), 'utf8');
      console.log("✅ 帖子数据文件初始化成功");
    }
  } catch (err) {
    console.error("❌ 帖子数据初始化失败：", err.message);
  }
};

initUserData();
initPostData();

// ===================== 工具函数 =====================
const getUsers = () => {
  try {
    const data = fs.readFileSync(USER_DATA_PATH, 'utf8');
    return JSON.parse(data || '[]');
  } catch (err) {
    console.error("❌ 读取用户数据失败：", err.message);
    return [];
  }
};

const saveUsers = (users) => {
  try {
    fs.writeFileSync(USER_DATA_PATH, JSON.stringify(users, null, 2), 'utf8');
  } catch (err) {
    console.error("❌ 保存用户数据失败：", err.message);
  }
};

const getPosts = () => {
  try {
    const data = fs.readFileSync(POST_DATA_PATH, 'utf8');
    return JSON.parse(data || '[]');
  } catch (err) {
    console.error("❌ 读取帖子数据失败：", err.message);
    return [];
  }
};

const savePosts = (posts) => {
  try {
    fs.writeFileSync(POST_DATA_PATH, JSON.stringify(posts, null, 2), 'utf8');
  } catch (err) {
    console.error("❌ 保存帖子数据失败：", err.message);
  }
};

const checkLogin = (req, res, next) => {
  if (!req.session.user) {
    return res.json({ success: false, msg: "请先登录后再操作！" });
  }
  next();
};

const checkAdmin = (req, res, next) => {
  if (!req.session.user || !req.session.user.isAdmin) {
    return res.json({ success: false, msg: "无管理员权限，无法执行此操作！" });
  }
  next();
};

// 防抖工具函数（用于搜索）
const debounce = (fn, delay) => {
  let timer = null;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      fn.apply(this, args);
    }, delay);
  };
};

// ===================== 验证码接口 =====================
app.get('/api/captcha', (req, res) => {
  try {
    const captcha = svgCaptcha.create({
      size: 4, noise: 3, color: true, width: 120, height: 40, ignoreChars: '0o1ilI'
    });
    req.session.captcha = captcha.text.toLowerCase();
    res.type('svg');
    res.send(captcha.data);
  } catch (err) {
    res.status(500).json({ success: false, msg: "生成验证码失败，请重试！" });
  }
});

// ===================== 注册/登录/登出接口 =====================
app.post('/api/register', (req, res) => {
  try {
    const { username, password, confirmPassword, captcha } = req.body;
    if (!username || !password || !confirmPassword || !captcha) {
      return res.json({ success: false, msg: "请填写所有必填字段！" });
    }
    if (password !== confirmPassword) return res.json({ success: false, msg: "两次密码不一致！" });
    if (password.length < 6) return res.json({ success: false, msg: "密码长度不能少于6位！" });
    if (captcha.toLowerCase() !== req.session.captcha) return res.json({ success: false, msg: "验证码错误！" });

    const users = getUsers();
    if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
      return res.json({ success: false, msg: "用户名已存在！" });
    }

    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);
    const newUser = {
      id: users.length > 0 ? Math.max(...users.map(u => u.id)) + 1 : 2,
      username: username.trim(),
      password: hashedPassword,
      avatar: "",
      isVerified: false,
      isAdmin: false,
      tags: [],
      createdAt: new Date().toISOString()
    };
    users.push(newUser);
    saveUsers(users);
    req.session.captcha = null;

    res.json({ success: true, msg: "注册成功！请登录", data: { username: newUser.username } });
  } catch (err) {
    console.error("❌ 注册失败：", err.message);
    res.json({ success: false, msg: "服务器内部错误，请稍后重试！" });
  }
});

app.post('/api/login', (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.json({ success: false, msg: "请输入用户名和密码！" });

    const users = getUsers();
    const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user) return res.json({ success: false, msg: "用户名不存在！" });
    if (!bcrypt.compareSync(password, user.password)) return res.json({ success: false, msg: "密码错误！" });

    const { password: _, ...userInfo } = user;
    req.session.user = userInfo;
    res.json({ success: true, msg: "登录成功！", data: userInfo });
  } catch (err) {
    console.error("❌ 登录失败：", err.message);
    res.json({ success: false, msg: "服务器内部错误，请稍后重试！" });
  }
});

app.post('/api/logout', checkLogin, (req, res) => {
  try {
    req.session.user = null;
    res.json({ success: true, msg: "登出成功！" });
  } catch (err) {
    res.json({ success: false, msg: "登出失败，请稍后重试！" });
  }
});

// ===================== 用户信息接口 =====================
app.get('/api/user/current', checkLogin, (req, res) => {
  res.json({ success: true, data: req.session.user });
});

app.post('/api/user/avatar', checkLogin, upload.single('avatar'), (req, res) => {
  try {
    if (!req.file) return res.json({ success: false, msg: "请选择头像文件！" });

    const users = getUsers();
    const userIndex = users.findIndex(u => u.id === req.session.user.id);
    if (userIndex === -1) return res.json({ success: false, msg: "用户不存在！" });

    const avatarUrl = `/assets/avatars/${req.file.filename}`;
    users[userIndex].avatar = avatarUrl;
    saveUsers(users);
    req.session.user.avatar = avatarUrl;

    res.json({ success: true, msg: "头像上传成功！", data: { avatar: avatarUrl } });
  } catch (err) {
    console.error("❌ 上传头像失败：", err.message);
    res.json({ success: false, msg: "头像上传失败，请稍后重试！" });
  }
});

app.post('/api/user/username', checkLogin, (req, res) => {
  try {
    const { newUsername } = req.body;
    if (!newUsername || newUsername.trim() === "") return res.json({ success: false, msg: "请输入新用户名！" });

    const users = getUsers();
    if (users.some(u => u.id !== req.session.user.id && u.username.toLowerCase() === newUsername.toLowerCase())) {
      return res.json({ success: false, msg: "新用户名已存在！" });
    }

    const userIndex = users.findIndex(u => u.id === req.session.user.id);
    users[userIndex].username = newUsername.trim();
    saveUsers(users);
    req.session.user.username = newUsername.trim();

    res.json({ success: true, msg: "用户名修改成功！", data: { username: newUsername.trim() } });
  } catch (err) {
    console.error("❌ 修改用户名失败：", err.message);
    res.json({ success: false, msg: "修改用户名失败，请稍后重试！" });
  }
});

// ===================== 管理员用户管理接口 =====================
app.get('/api/admin/users', checkAdmin, (req, res) => {
  try {
    const users = getUsers();
    const safeUsers = users.map(({ password, ...rest }) => rest);
    res.json({ success: true, data: safeUsers });
  } catch (err) {
    res.json({ success: false, msg: "获取用户列表失败！" });
  }
});

// 新增：管理员用户搜索接口
app.get('/api/admin/users/search', checkAdmin, (req, res) => {
  try {
    const { keyword } = req.query;
    if (!keyword || keyword.trim() === "") {
      return res.json({ success: false, msg: "请输入搜索关键词！" });
    }
    const users = getUsers();
    const safeUsers = users.map(({ password, ...rest }) => rest);
    // 按用户名模糊搜索（不区分大小写）
    const filteredUsers = safeUsers.filter(user => 
      user.username.toLowerCase().includes(keyword.trim().toLowerCase())
    );
    res.json({ success: true, data: filteredUsers });
  } catch (err) {
    res.json({ success: false, msg: "用户搜索失败，请稍后重试！" });
  }
});

app.post('/api/admin/verify', checkAdmin, (req, res) => {
  try {
    const { userId, isVerified } = req.body;
    if (!userId || isVerified === undefined) return res.json({ success: false, msg: "请填写用户ID和蓝标状态！" });

    const users = getUsers();
    const userIndex = users.findIndex(u => u.id === Number(userId));
    if (userIndex === -1) return res.json({ success: false, msg: "用户不存在！" });

    users[userIndex].isVerified = Boolean(isVerified);
    saveUsers(users);
    res.json({
      success: true,
      msg: isVerified ? "蓝标授予成功！" : "蓝标取消成功！",
      data: { userId, isVerified: Boolean(isVerified) }
    });
  } catch (err) {
    console.error("❌ 蓝标管理失败：", err.message);
    res.json({ success: false, msg: "操作失败，请稍后重试！" });
  }
});

app.post('/api/admin/addTag', checkAdmin, (req, res) => {
  try {
    const { userId, tag } = req.body;
    if (!userId || !tag || tag.trim() === "") return res.json({ success: false, msg: "请填写用户ID和标签！" });

    const users = getUsers();
    const userIndex = users.findIndex(u => u.id === Number(userId));
    if (userIndex === -1) return res.json({ success: false, msg: "用户不存在！" });

    const tagTrim = tag.trim();
    if (users[userIndex].tags.includes(tagTrim)) return res.json({ success: false, msg: "该用户已拥有此标签！" });

    users[userIndex].tags.push(tagTrim);
    saveUsers(users);
    res.json({ success: true, msg: "标签添加成功！", data: { userId, tags: users[userIndex].tags } });
  } catch (err) {
    console.error("❌ 添加标签失败：", err.message);
    res.json({ success: false, msg: "操作失败，请稍后重试！" });
  }
});

app.post('/api/admin/removeTag', checkAdmin, (req, res) => {
  try {
    const { userId, tag } = req.body;
    if (!userId || !tag) return res.json({ success: false, msg: "请填写用户ID和标签！" });

    const users = getUsers();
    const userIndex = users.findIndex(u => u.id === Number(userId));
    if (userIndex === -1) return res.json({ success: false, msg: "用户不存在！" });

    const tagTrim = tag.trim();
    users[userIndex].tags = users[userIndex].tags.filter(t => t !== tagTrim);
    saveUsers(users);
    res.json({ success: true, msg: "标签移除成功！", data: { userId, tags: users[userIndex].tags } });
  } catch (err) {
    console.error("❌ 移除标签失败：", err.message);
    res.json({ success: false, msg: "操作失败，请稍后重试！" });
  }
});

app.post('/api/admin/setAdmin', checkAdmin, (req, res) => {
  try {
    const { userId, isAdmin } = req.body;
    if (!userId || isAdmin === undefined) return res.json({ success: false, msg: "请填写用户ID和管理员状态！" });
    if (Number(userId) === 1) return res.json({ success: false, msg: "禁止修改官方账号的管理员权限！" });

    const users = getUsers();
    const userIndex = users.findIndex(u => u.id === Number(userId));
    if (userIndex === -1) return res.json({ success: false, msg: "用户不存在！" });

    users[userIndex].isAdmin = Boolean(isAdmin);
    saveUsers(users);
    res.json({
      success: true,
      msg: isAdmin ? "管理员添加成功！" : "管理员移除成功！",
      data: { userId, isAdmin: Boolean(isAdmin) }
    });
  } catch (err) {
    console.error("❌ 管理员权限管理失败：", err.message);
    res.json({ success: false, msg: "操作失败，请稍后重试！" });
  }
});

// ===================== 管理员帖子管理接口 =====================
app.get('/api/admin/posts', checkAdmin, (req, res) => {
  try {
    const posts = getPosts();
    res.json({ success: true, data: posts });
  } catch (err) {
    res.json({ success: false, msg: "获取帖子列表失败！" });
  }
});

// 新增：管理员帖子搜索接口（按内容/用户名）
app.get('/api/admin/posts/search', checkAdmin, (req, res) => {
  try {
    const { keyword } = req.query;
    if (!keyword || keyword.trim() === "") {
      return res.json({ success: false, msg: "请输入搜索关键词！" });
    }
    const posts = getPosts();
    // 按帖子内容、用户名模糊搜索（不区分大小写）
    const filteredPosts = posts.filter(post => 
      post.content.toLowerCase().includes(keyword.trim().toLowerCase()) ||
      post.username.toLowerCase().includes(keyword.trim().toLowerCase())
    );
    res.json({ success: true, data: filteredPosts });
  } catch (err) {
    res.json({ success: false, msg: "帖子搜索失败，请稍后重试！" });
  }
});

app.post('/api/admin/post/delete', checkAdmin, (req, res) => {
  try {
    const { postId } = req.body;
    if (!postId) return res.json({ success: false, msg: "请选择要删除的帖子！" });

    const posts = getPosts();
    const postIndex = posts.findIndex(p => p.id === Number(postId));
    if (postIndex === -1) return res.json({ success: false, msg: "帖子不存在！" });

    posts.splice(postIndex, 1);
    savePosts(posts);
    res.json({ success: true, msg: "删除帖子成功！" });
  } catch (err) {
    res.json({ success: false, msg: "删除帖子失败！" });
  }
});

app.post('/api/admin/comment/delete', checkAdmin, (req, res) => {
  try {
    const { postId, commentId } = req.body;
    if (!postId || !commentId) return res.json({ success: false, msg: "请填写帖子ID和评论ID！" });

    const posts = getPosts();
    const postIndex = posts.findIndex(p => p.id === Number(postId));
    if (postIndex === -1) return res.json({ success: false, msg: "帖子不存在！" });

    const post = posts[postIndex];
    const commentIndex = post.comments.findIndex(c => c.id === Number(commentId));
    if (commentIndex === -1) return res.json({ success: false, msg: "评论不存在！" });

    post.comments.splice(commentIndex, 1);
    savePosts(posts);
    res.json({ success: true, msg: "删除评论成功！" });
  } catch (err) {
    res.json({ success: false, msg: "删除评论失败！" });
  }
});

// ===================== 论坛帖子接口 =====================
app.post('/api/posts/create', checkLogin, (req, res) => {
  try {
    const { content } = req.body;
    if (!content || content.trim() === "") return res.json({ success: false, msg: "帖子内容不能为空！" });

    const posts = getPosts();
    const newPost = {
      id: posts.length > 0 ? Math.max(...posts.map(p => p.id)) + 1 : 1,
      userId: req.session.user.id,
      username: req.session.user.username,
      userAvatar: req.session.user.avatar,
      userIsVerified: req.session.user.isVerified,
      content: content.trim(),
      likes: 0,
      likedBy: [],
      comments: [],
      createdAt: new Date().toISOString()
    };
    posts.push(newPost);
    savePosts(posts);

    res.json({ success: true, msg: "帖子发布成功！", data: newPost });
  } catch (err) {
    console.error("❌ 发布帖子失败：", err.message);
    res.json({ success: false, msg: "帖子发布失败，请稍后重试！" });
  }
});

app.post('/api/posts/like', checkLogin, (req, res) => {
  try {
    const { postId } = req.body;
    if (!postId) return res.json({ success: false, msg: "请选择要点赞的帖子！" });

    const posts = getPosts();
    const postIndex = posts.findIndex(p => p.id === Number(postId));
    if (postIndex === -1) return res.json({ success: false, msg: "帖子不存在！" });

    const post = posts[postIndex];
    const userId = req.session.user.id;
    if (post.likedBy.includes(userId)) {
      post.likedBy = post.likedBy.filter(id => id !== userId);
    } else {
      post.likedBy.push(userId);
    }
    post.likes = post.likedBy.length;
    savePosts(posts);

    res.json({
      success: true,
      msg: post.likedBy.includes(userId) ? "点赞成功！" : "取消点赞成功！",
      data: { liked: post.likedBy.includes(userId), likes: post.likes }
    });
  } catch (err) {
    console.error("❌ 点赞失败：", err.message);
    res.json({ success: false, msg: "操作失败，请稍后重试！" });
  }
});

app.post('/api/posts/comment', checkLogin, (req, res) => {
  try {
    const { postId, content } = req.body;
    if (!postId || !content || content.trim() === "") return res.json({ success: false, msg: "评论内容不能为空！" });

    const posts = getPosts();
    const postIndex = posts.findIndex(p => p.id === Number(postId));
    if (postIndex === -1) return res.json({ success: false, msg: "帖子不存在！" });

    const post = posts[postIndex];
    const newComment = {
      id: post.comments.length > 0 ? Math.max(...post.comments.map(c => c.id)) + 1 : 1,
      userId: req.session.user.id,
      username: req.session.user.username,
      userAvatar: req.session.user.avatar,
      userIsVerified: req.session.user.isVerified,
      content: content.trim(),
      createdAt: new Date().toISOString()
    };
    post.comments.push(newComment);
    savePosts(posts);

    res.json({ success: true, msg: "评论成功！", data: newComment });
  } catch (err) {
    console.error("❌ 评论失败：", err.message);
    res.json({ success: false, msg: "评论失败，请稍后重试！" });
  }
});

app.get('/api/posts', (req, res) => {
  try {
    const posts = getPosts();
    const sortedPosts = posts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json({ success: true, data: sortedPosts });
  } catch (err) {
    res.json({ success: false, msg: "获取帖子失败！" });
  }
});

// 新增：主页帖子搜索接口（按内容搜索）
app.get('/api/posts/search', (req, res) => {
  try {
    const { keyword } = req.query;
    if (!keyword || keyword.trim() === "") {
      return res.json({ success: false, msg: "请输入搜索关键词！" });
    }
    const posts = getPosts();
    const sortedPosts = posts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    // 按帖子内容模糊搜索（不区分大小写）
    const filteredPosts = sortedPosts.filter(post => 
      post.content.toLowerCase().includes(keyword.trim().toLowerCase())
    );
    res.json({ success: true, data: filteredPosts });
  } catch (err) {
    res.json({ success: false, msg: "帖子搜索失败，请稍后重试！" });
  }
});

// ===================== 启动服务器 =====================
app.listen(PORT, () => {
  console.log(`\n🚀 VTCRP论坛服务器已启动！`);
  console.log(`🔗 访问地址：http://localhost:${PORT}`);
  console.log(`📌 登录页：http://localhost:${PORT}/login.html`);
  console.log(`📌 注册页：http://localhost:${PORT}/register.html`);
  console.log(`\n🔑 官方账号：`);
  console.log(`   用户名：VTCRP Official`);
  console.log(`   密码：VTCRP_Official_2026`);
});

// ===================== 全局错误处理 =====================
app.use((err, req, res, next) => {
  console.error("❌ 全局错误：", err.stack);
  res.status(500).json({ success: false, msg: "服务器内部错误，请联系管理员！" });
});