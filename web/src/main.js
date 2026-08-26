import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import * as Icons from '@element-plus/icons-vue'
import App from './App.vue'
import router from './router'
import './styles/global.css'

const app = createApp(App)
// 全量注册图标（菜单/按钮按名称动态引用）
for (const [name, comp] of Object.entries(Icons)) app.component(name, comp)
app.use(ElementPlus).use(router).mount('#app')
