import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import cors from 'cors';

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your-secret-key'; // 在生产环境中，应该使用环境变量

app.use(cors());
app.use(express.json());

// 模拟用户数据库
const users = [
  { id: 1, username: 'doctor1', password: '$2b$10$Ow4GHgJJsZCNNQXXOZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ' },
];

// 模拟AI模型
function mockAIModel(patientData) {
  // 在实际场景中，这里会是您的AI模型的预测逻辑
  return [
    { name: "药物X", confidence: 0.9 },
    { name: "药物Y", confidence: 0.75 },
    { name: "药物Z", confidence: 0.6 },
  ];
}

// 身份验证中间件
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// 登录路由
app.post('/login', async (req, res) => {
  const user = users.find(u => u.username === req.body.username);
  if (user == null) {
    return res.status(400).send('找不到用户');
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      const accessToken = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
      res.json({ accessToken: accessToken });
    } else {
      res.send('不允许访问');
    }
  } catch {
    res.status(500).send();
  }
});

// 药物推荐路由
app.post('/recommend', authenticateToken, (req, res) => {
  const patientData = req.body;
  const recommendations = mockAIModel(patientData);
  res.json(recommendations);
});

app.listen(PORT, () => {
  console.log(`服务器运行在端口 ${PORT}`);
});

// 为了演示目的，让我们创建一个新用户
bcrypt.hash('password123', 10, (err, hash) => {
  if (err) {
    console.error('密码哈希错误:', err);
  } else {
    console.log('演示用的哈希密码:', hash);
    // 在实际应用中，您会将这个哈希值保存到数据库中
  }
});
'use client'

import { useState } from 'react'
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"

export default function DrugRecommendationSystem() {
  const [patientData, setPatientData] = useState({
    age: '',
    gender: '',
    symptoms: '',
    medicalHistory: ''
  })
  const [recommendations, setRecommendations] = useState([])
  const [token, setToken] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  const handleInputChange = (e) => {
    const { name, value } = e.target
    setPatientData(prev => ({ ...prev, [name]: value }))
  }

  const handleLogin = async (e) => {
    e.preventDefault()
    try {
      const response = await fetch('http://localhost:3000/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      })
      const data = await response.json()
      setToken(data.accessToken)
    } catch (error) {
      console.error('登录错误:', error)
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    try {
      const response = await fetch('http://localhost:3000/recommend', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(patientData),
      })
      const data = await response.json()
      setRecommendations(data)
    } catch (error) {
      console.error('推荐错误:', error)
    }
  }

  if (!token) {
    return (
      <div className="container mx-auto p-4">
        <Card>
          <CardHeader>
            <CardTitle>登录</CardTitle>
            <CardDescription>请登录以访问系统</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <Label htmlFor="username">用户名</Label>
                <Input
                  id="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                />
              </div>
              <div>
                <Label htmlFor="password">密码</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>
              <Button type="submit">登录</Button>
            </form>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-2xl font-bold mb-4">AI药物推荐系统</h1>
      <Card>
        <CardHeader>
          <CardTitle>患者信息</CardTitle>
          <CardDescription>输入患者详细信息以获取药物推荐</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <Label htmlFor="age">年龄</Label>
              <Input
                id="age"
                name="age"
                type="number"
                value={patientData.age}
                onChange={handleInputChange}
                required
              />
            </div>
            <div>
              <Label htmlFor="gender">性别</Label>
              <Input
                id="gender"
                name="gender"
                type="text"
                value={patientData.gender}
                onChange={handleInputChange}
                required
              />
            </div>
            <div>
              <Label htmlFor="symptoms">症状</Label>
              <Input
                id="symptoms"
                name="symptoms"
                type="text"
                value={patientData.symptoms}
                onChange={handleInputChange}
                required
              />
            </div>
            <div>
              <Label htmlFor="medicalHistory">病史</Label>
              <Input
                id="medicalHistory"
                name="medicalHistory"
                type="text"
                value={patientData.medicalHistory}
                onChange={handleInputChange}
              />
            </div>
            <Button type="submit">获取推荐</Button>
          </form>
        </CardContent>
      </Card>

      {recommendations.length > 0 && (
        <Card className="mt-4">
          <CardHeader>
            <CardTitle>推荐药物</CardTitle>
          </CardHeader>
          <CardContent>
            <ul>
              {recommendations.map((drug, index) => (
                <li key={index} className="mb-2">
                  {drug.name} (置信度: {(drug.confidence * 100).toFixed(2)}%)
                </li>
              ))}
            </ul>
          </CardContent>
          <CardFooter>
            <p className="text-sm text-gray-500">
              在做出任何医疗决定之前，请咨询医疗专业人员。
            </p>
          </CardFooter>
        </Card>
      )}
    </div>
  )
}

