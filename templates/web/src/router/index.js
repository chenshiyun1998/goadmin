import Vue from 'vue'
import Router from 'vue-router'
import {routes} from './routes'
import store from '@/store'
//import { Message } from 'element-ui'
import NProgress from 'nprogress' // progress bar
import 'nprogress/nprogress.css'// progress bar style
import { LocalAccount } from '@/api/local-account'

NProgress.configure({ showSpinner: false })// NProgress Configuration

const CLIENT = 'webadmin_'
const LOGIN_URL = '/login'
const DEFAULT_URL = '/'

Vue.use(Router)
const router = new Router({
  scrollBehavior: () => ({ y: 0 }),
  mode: 'history',
  routes: routes
})

router.beforeEach((to, from, next) => {
  if (!LocalAccount.isAuth() && to.path !== LOGIN_URL) {
    next(LOGIN_URL)
  } else if (LocalAccount.isAuth()) {
    if (!store.getters.isLoadedRoutes && (!store.getters.addRouters || store.getters.addRouters.length === 0)) {
      store.dispatch('GenerateRoutes', LocalAccount.getRouteLinks()).then(() => { // 生成可访问的路由表
        router.addRoutes(store.getters.addRouters) 
        store.dispatch('setIsLoadedRoutes', true)
        if (to.path === LOGIN_URL || to.path === '/') {
          next(DEFAULT_URL)
        } else {
          next({ ...to, replace: true })
        }
      })
    } else {
      if (to.path === LOGIN_URL || to.path === '/') {
        next(DEFAULT_URL)
      } else {
        next()
      }
    }
  } else {
    next()
  }
})

router.afterEach(() => {
  NProgress.done()
})

export default router
