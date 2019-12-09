import Layout from '@/views/layout/Layout'
export const constantRouterMap = [
    { path: '/login', component: () => import('@/views/login/index'), hidden: true },
    { path: '/authredirect', component: () => import('@/views/login/authredirect'), hidden: true },
    {
        path: '',
        component: Layout,
        redirect: 'dashboard',
        children: [{
            path: 'dashboard',
            component: () => import('@/views/dashboard/index'),
            name: 'dashboard',
            meta: { title: '首页', icon: 'dashboard', noCache: true }
        }]
    }
]

export const asyncRouterMap = [
    {
        path: '/base',
        component: Layout,
        redirect: 'noredirect',
        name: 'base',
        meta: {
            title: '基础管理',
            icon: 'component'
        },
        children: [
            { path: 'service_providers', component: () => import('@/views/base/service_providers'), name: 'service_providers', meta: { title: '服务商管理', noCache: true } },
            { path: 'banks', component: () => import('@/views/base/banks'), name: 'banks', meta: { title: '银行管理', noCache: true } },
        ]
    },{
        path: '/sys',
        component: Layout,
        redirect: 'noredirect',
        name: 'sys',
        meta: {
            title: '系统管理',
            icon: 'xitong'
        },
        children: [
            { path: 'menus', component: () => import('@/views/sys/menus'), name: 'menus', meta: { title: '菜单管理', noCache: false } },
            { path: 'org_types', component: () => import('@/views/sys/org_types'), name: 'org_types', meta: { title: '机构类型', noCache: true } },
            { path: 'roles', component: () => import('@/views/sys/roles'), name: 'roles', meta: { title: '角色管理', noCache: true } },
            { path: 'role_menu', component: () => import('@/views/sys/role_menu'), name: 'menus', meta: { title: '权限设置', noCache: false }, hidden: true },
            { path: 'employees', component: () => import('@/views/sys/employees'), name: 'employees', meta: { title: '员工管理', noCache: true } },
            { path: 'employee_edit', component: () => import('@/views/sys/employee_edit'), name: 'employee_edit', meta: { title: '用户编辑', noCache: true }, hidden: true },
            { path: 'employee_update_password', component: () => import('@/views/sys/employee_update_password'), name: 'employee_update_password', meta: { title: '修改密码', noCache: true }, hidden: true },
        ]
    }
]

export const routes = constantRouterMap