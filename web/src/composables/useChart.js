// ECharts 生命周期封装：init / setOption / resize / dispose
import * as echarts from 'echarts'
import { onBeforeUnmount, onMounted, shallowRef } from 'vue'

/**
 * @param elRef 模板 ref
 * @param optionFactory 返回 ECharts option 的函数（render 时求值）
 * @returns { chart, render, resize }
 */
export function useChart(elRef, optionFactory) {
  const chart = shallowRef(null)

  const render = () => {
    if (!elRef.value) return
    if (!chart.value) chart.value = echarts.init(elRef.value)
    chart.value.setOption(optionFactory())
  }
  const resize = () => chart.value && chart.value.resize()

  onMounted(() => {
    render()
    window.addEventListener('resize', resize)
  })
  onBeforeUnmount(() => {
    window.removeEventListener('resize', resize)
    if (chart.value) { chart.value.dispose(); chart.value = null }
  })

  return { chart, render, resize }
}
