import axios from '../utils/axios'

// 登录
export const loginRequest = params => { return axios.post(`/v1/admin_api/login`, params).then(res => res.data) }

// 员工管理
export const findEmployees = params => { return axios.get(`/v1/admin_api/employee/query`, { params: params }).then(res => res.data) }
export const getEmployee = params => { return axios.get(`/v1/admin_api/employee/get`, { params: params }).then(res => res.data) }
export const saveEmployee = params => { return axios.post(`/v1/admin_api/employee/save`, params).then(res => res.data) }
export const deleteEmployee = params => { return axios.delete(`/v1/admin_api/employee/delete`, { params: params }).then(res => res.data) }
export const delEmployees = params => { return axios.post(`/v1/admin_api/employee/dels`, params).then(res => res.data) }
export const updatePasswordEmployee = params => { return axios.post(`/v1/admin_api/employee/update_password`, params).then(res => res.data) }
export const resetPasswordEmployee = params => { return axios.post(`/v1/admin_api/employee/reset_password`, params).then(res => res.data) }

// 角色菜单
export const findSysMenus = params => { return axios.get(`/v1/admin_api/sys_menu/query`, { params: params }).then(res => res.data) }
export const saveSysMenu = params => { return axios.post(`/v1/admin_api/sys_menu/save`, params).then(res => res.data) }
export const deleteSysMenu = params => { return axios.get(`/v1/admin_api/sys_menu/delete`, { params: params }).then(res => res.data) }
export const findRoles = params => { return axios.get(`/v1/admin_api/role/query`, { params: params }).then(res => res.data) }
export const saveRole = params => { return axios.post(`/v1/admin_api/role/save`, params).then(res => res.data) }
export const delRole = params => { return axios.get(`/v1/admin_api/role/del`, {params}).then(res => res.data) }
export const findRoleMenus = params => { return axios.get(`/v1/admin_api/role_menu/query`, { params: params }).then(res => res.data) }
export const saveRoleMenus = params => { return axios.post(`/v1/admin_api/role_menu/save`, params).then(res => res.data) }

// 机构类型
export const findOrgTypesTree = params => { return axios.get(`/v1/admin_api/org_type/query_by_tree`, { params: params }).then(res => res.data) }
export const findOrgTypesSelect = params => { return axios.get(`/v1/admin_api/org_type/query_by_select`, { params: params }).then(res => res.data) }
export const saveOrgType = params => { return axios.post(`/v1/admin_api/org_type/save`, params).then(res => res.data) }

${api_rows}