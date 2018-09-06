package com.jian.ssm.shiro;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;
import com.jian.ssm.entity.UserRole;
import com.jian.ssm.service.UserRoleService;

public class CustomRealm   extends  AuthorizingRealm{
	@Autowired
	UserRoleService   us ;
   /**
    * 权限认证
    */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection arg0) {
		
		return null;
	}
     /**
      * 身份认证
      */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		UsernamePasswordToken  uPasswordToken  = (UsernamePasswordToken) token ;
		String userName = (String) uPasswordToken.getPrincipal();
		String Pwd = new String((char[])uPasswordToken.getCredentials());
	    UserRole  ur =	us.selectUser(userName);
	    if(ur == null){
	    	throw new  UnknownAccountException("账号不存在");
	    }
	    Pwd  = new Md5Hash(Pwd).toHex();
	    
		// 密码错误
		if (!Pwd.equals(ur.getPassword())) {
			throw new IncorrectCredentialsException("账号或密码不正确!");
		}
		
	
        SimpleAuthenticationInfo  simpleAuthenticationInfo  = new SimpleAuthenticationInfo(ur, Pwd, this.getName());
		return simpleAuthenticationInfo;
	}

}
