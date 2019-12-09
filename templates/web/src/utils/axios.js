import axios from 'axios'
import qs from 'qs'
import {LocalAccount} from '../api/local-account'
import { Notification } from 'element-ui'
import 'nprogress/nprogress.css'
import NProgress from 'nprogress'
import router from '../router'

axios.defaults.timeout = 45000
axios.defaults.baseURL = process.env.BASE_API
axios.defaults.headers.common['Content-Type'] = 'application/json;charset=UTF-8'

const CLIENT = 'webadmin_'
var timestamp = Date.now()

//添加请求拦截器
axios.interceptors.request.use(function(req) {
    NProgress.start()
    req.headers['X-Client-Id'] = CLIENT + timestamp
    //在发送请求之前做某事
    if (LocalAccount.isAuth() && LocalAccount.getToken()) {
      req.headers['X-Token'] = 'Bearer ' + LocalAccount.getToken()
    } else {
      LocalAccount.clear()
      router.push('/login')
    }

    return req
  }, function(error) {
    //请求错误时做些事
    NProgress.done()
    Notification.error({title: '服务器错误', message: '请检查网络是否异常', duration: 2000})
    return Promise.reject(error)
})

//添加响应拦截器
axios.interceptors.response.use(function(response) {
    NProgress.done()
   //对响应数据做些事
   if (response.data.code === 501) {
      LocalAccount.clear()
      router.push('/login')
      //Notification.error({title: '请求错误', message: response.data.msg, duration: 2000})
   } else if (response.data.code !== 0) {
      Notification.error({title: '系统提示', message: response.data.msg, duration: 3000})
   }
   return response
 }, function(error) {
   //请求错误时做些事
   NProgress.done()
   Notification.error({title: '服务器错误', message: '请检查网络是否异常', duration: 2000})
   return Promise.reject(error)
 })

 export default axios
