import { createRouter, createWebHistory } from 'vue-router'
import { getToken } from './api'

const routes = [
  { path: '/login', component: () => import('./views/Login.vue'), meta: { title: '登录' } },
  {
    path: '/',
    component: () => import('./layout/MainLayout.vue'),
    redirect: '/dashboard',
    children: [
      { path: 'dashboard', component: () => import('./views/Dashboard.vue'), meta: { title: '安全总览', icon: 'Odometer' } },
      { path: 'hosts', component: () => import('./views/Hosts.vue'), meta: { title: '主机管理', icon: 'Monitor' } },
      { path: 'baseline', component: () => import('./views/Baseline.vue'), meta: { title: '基线核查', icon: 'Checked' } },
      { path: 'baseline-templates', component: () => import('./views/BaselineTemplates.vue'), meta: { title: '基线模板', icon: 'DocumentChecked' } },
      { path: 'vuln', component: () => import('./views/Vuln.vue'), meta: { title: '漏洞与修复', icon: 'Warning' } },
      { path: 'virus', component: () => import('./views/Virus.vue'), meta: { title: '病毒查杀', icon: 'Search' } },
      { path: 'libraries', component: () => import('./views/Libraries.vue'), meta: { title: '安全库管理', icon: 'Collection' } },
      { path: 'protect', component: () => import('./views/Protect.vue'), meta: { title: '实时防护', icon: 'Lock' } },
      { path: 'alerts', component: () => import('./views/Alerts.vue'), meta: { title: '告警中心', icon: 'Bell' } },
      { path: 'system', component: () => import('./views/System.vue'), meta: { title: '系统管理', icon: 'Setting' } },
    ]
  },
  // 安全大屏：独立全屏路由（不带控制台布局）
  { path: '/screen', component: () => import('./views/Screen.vue'), meta: { title: '安全态势感知大屏' } },
  { path: '/:pathMatch(.*)*', redirect: '/dashboard' }
]

const router = createRouter({ history: createWebHistory(), routes })

// 认证守卫：未登录一律跳登录页（screen 大屏同 JWT 策略）
router.beforeEach(to => {
  if (to.path === '/login') return true
  if (!getToken()) return { path: '/login', query: { redirect: to.fullPath } }
  return true
})

router.afterEach(to => {
  document.title = to.meta.title ? `${to.meta.title} · ALinkSec` : 'ALinkSec 主机安全平台'
})

export default router
