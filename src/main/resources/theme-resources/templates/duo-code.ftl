<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "title">
    MFA Enter Code
    <#elseif section = "header">
    MFA Enter Code
    <#elseif section = "form">
        <form id="loginform" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <#if capability = "sms">
                Please enter the passcode we just texted you:<br />
                </#if>
                <#if capability = "mobile_otp">
                Please enter the passcode shown in your Duo Mobile app:<br />
                </#if>
                <#if capability = "token">
                Please enter the passcode from your hardware token:<br />
                </#if>
                <input tabindex="1" id="passcode" class="${properties.kcInputClass!}" name="passcode" value="" type="text" autofocus autocomplete="off" />

                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <div class="${properties.kcFormButtonsWrapperClass!}">
                          <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" name="continue" id="kc-continue" type="submit" value="Continue"/><br /><br />
                          <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" name="restart" id="kc-cancel" type="submit" value="Start Over"/><br /><br />
                    </div>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>