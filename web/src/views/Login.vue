<template>
  <div class="login-bg">
    <div class="login-card">
      <div class="hd">
        <div class="mark">AS</div>
        <div><b>ALinkSec</b><small>主机安全监测管理平台</small></div>
      </div>
      <el-form :model="form" size="large" @keyup.enter="submit">
        <el-form-item>
          <el-input v-model="form.user" placeholder="用户名" :prefix-icon="User" />
        </el-form-item>
        <el-form-item>
          <el-input v-model="form.pass" type="password" placeholder="密码" show-password :prefix-icon="Lock" />
        </el-form-item>
        <el-button type="primary" size="large" style="width:100%" :loading="loading" @click="submit">登 录</el-button>
      </el-form>
      <p class="tip">默认账号 admin / Admin@123 · 首次登录后请修改密码</p>
    </div>
    <div class="foot">ALINKSEC SECURITY PLATFORM</div>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { User, Lock } from '@element-plus/icons-vue'
import { login } from '../api'

const router = useRouter()
const route = useRoute()
const form = reactive({ user: '', pass: '' })
const loading = ref(false)

const submit = async () => {
  if (!form.user || !form.pass) return ElMessage.warning('请输入用户名和密码')
  loading.value = true
  try {
    await login(form.user.trim(), form.pass)
    ElMessage.success('登录成功')
    router.push(route.query.redirect || '/')
  } catch (e) {
    ElMessage.error(e.message || '登录失败')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-bg {
  height: 100%; display: flex; align-items: center; justify-content: center; position: relative;
  background: radial-gradient(1200px 700px at 50% -10%, #0a2547 0%, #04102b 45%, #020617 100%);
}
.login-bg::before {
  content: ""; position: absolute; inset: 0; pointer-events: none;
  background-image: linear-gradient(rgba(0,229,255,.035) 1px, transparent 1px), linear-gradient(90deg, rgba(0,229,255,.035) 1px, transparent 1px);
  background-size: 48px 48px;
}
.login-card {
  width: 380px; background: rgba(8, 28, 58, .85); border: 1px solid rgba(0, 229, 255, .22);
  box-shadow: inset 0 0 32px rgba(0, 120, 255, .08); border-radius: 10px; padding: 36px 32px 28px;
  position: relative;
}
.login-card::before, .login-card::after { content: ""; position: absolute; width: 14px; height: 14px; }
.login-card::before { left: -1px; top: -1px; border-left: 2px solid #00e5ff; border-top: 2px solid #00e5ff; }
.login-card::after { right: -1px; bottom: -1px; border-right: 2px solid #00e5ff; border-bottom: 2px solid #00e5ff; }
.hd { display: flex; align-items: center; gap: 12px; margin-bottom: 26px; }
.hd .mark {
  width: 40px; height: 40px; border-radius: 9px; background: linear-gradient(135deg, #00e5ff, #2f7bff);
  display: flex; align-items: center; justify-content: center; color: #04102b; font-weight: 800; font-size: 15px;
}
.hd b { color: #e8f6ff; font-size: 18px; letter-spacing: 2px; }
.hd small { display: block; color: #4d7cb8; font-size: 11px; letter-spacing: 1px; }
.tip { margin-top: 16px; text-align: center; font-size: 11px; color: #4d7cb8; }
.foot { position: absolute; bottom: 20px; width: 100%; text-align: center; font-size: 11px; color: #2e5386; letter-spacing: 2px; }
</style>
