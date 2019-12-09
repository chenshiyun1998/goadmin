import { asyncRouterMap, constantRouterMap } from '@/router/routes'

/**
 * 通过meta.role判断是否与当前用户权限匹配
 * @param roles
 * @param route
 */
function hasPermission(route_links, route) {
  if (route.meta && route.meta.roles) {
    return roles.some(role => route.meta.roles.indexOf(role) >= 0)
  } else {
    return true
  }
}

/**
 * 递归过滤异步路由表，返回符合用户角色权限的路由表
 * @param asyncRouterMap
 * @param roles
 */
function filterAsyncRouter(asyncRouterMap, root_path, route_links, level) {
  const accessedRouters = asyncRouterMap.filter(route => {
    if (level === "level1") {
      root_path = route.path
    }

    if (level === 'level2') {
      let route_path = root_path + "/" + route.path   
      if (_.indexOf(route_links, route_path) > -1 || route.hidden) {
        return true
      }
    }

    if (route.children && route.children.length) {
      route.children = filterAsyncRouter(route.children, root_path, route_links, "level2")

      let hidden_menus = _.filter(route.children, { hidden: true })
      if (route.children && route.children.length && hidden_menus.length < route.children.length) {
        return true
      }
    }

    return false
  })

  return accessedRouters
}

const permission = {
  state: {
    routers: constantRouterMap,
    addRouters: []
  },
  mutations: {
    SET_ROUTERS: (state, routers) => {
      state.addRouters = routers
      state.routers = constantRouterMap.concat(routers)
    }
  },
  actions: {
    GenerateRoutes({ commit }, route_links) {
      return new Promise(resolve => {  
        if (route_links && route_links.length > 0) {
        let  accessedRouters = filterAsyncRouter(asyncRouterMap, "", route_links, "level1")
          commit('SET_ROUTERS', accessedRouters)
        }
        resolve()
      })
    }
  }
}

export default permission
