<template>
  <div class="layout">
    <!-- 侧边栏 -->
    <aside class="sidebar">
      <div class="logo">
        <div class="mark">AS</div>
        <div><b>ALinkSec</b><small>主机安全监测管理平台</small></div>
      </div>
      <nav class="nav">
        <div v-for="m in menus" :key="m.path" class="nav-item"
             :class="{ active: route.path === m.path }" @click="router.push(m.path)">
          <el-icon><component :is="m.icon" /></el-icon><span>{{ m.title }}</span>
        </div>
      </nav>
      <div class="sidebar-foot">v1.0.0 · M2<br/>数据源：Agent 实采</div>
    </aside>

    <!-- 主区域 -->
    <div class="main">
      <header class="topbar">
        <div class="crumb">
          ALinkSec <el-icon><ArrowRight /></el-icon> <b>{{ route.meta.title }}</b>
        </div>
        <div class="topbar-right">
          <el-button size="small" type="primary" plain @click="router.push('/screen')">
            <el-icon style="margin-right:4px"><DataLine /></el-icon>安全大屏
          </el-button>
          <el-badge :value="17" :offset="[-2, 2]"><el-icon :size="18" color="#475569"><Bell /></el-icon></el-badge>
          <el-dropdown>
            <span style="display:flex;align-items:center;gap:8px;cursor:pointer">
              <el-avatar :size="30" style="background:#2563eb">{{ (user?.username || 'A')[0].toUpperCase() }}</el-avatar>
              <span style="font-size:13px">{{ user?.nickname || user?.username || '管理员' }}</span>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item>个人设置</el-dropdown-item>
                <el-dropdown-item divided @click="logout">退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </header>

      <main class="content">
        <router-view />
      </main>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessageBox } from 'element-plus'
import { getUser, logout as apiLogout } from '../api'

const route = useRoute()
const router = useRouter()
const user = computed(() => getUser())

// 菜单由 router 子路由 meta 驱动，增删页面只改 router.js
const menus = router.getRoutes()
  .filter(r => r.path !== '/' && r.meta?.title && r.meta?.icon)
  .map(r => ({ path: r.path, title: r.meta.title, icon: r.meta.icon }))

const logout = async () => {
  try { await ElMessageBox.confirm('确定退出登录？', '提示', { type: 'warning' }) } catch { return }
  await apiLogout()
  router.push('/login')
}
</script>
