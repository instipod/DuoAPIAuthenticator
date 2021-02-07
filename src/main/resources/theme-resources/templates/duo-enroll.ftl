<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "title">
    MFA Enrollment Required
    <#elseif section = "header">
    MFA Enrollment Required
    <#elseif section = "form">
        <form id="loginform" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                Your administrator requires that you set up multifactor authentication before continuing your login.<br />
                Click the Enroll button to begin, and then click Continue when you have finished enrolling.<br />
                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <div class="${properties.kcFormButtonsWrapperClass!}">
                          <a class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" id="kc-enroll" href="javascript:window.open('${enrollUrl}', 'Enroll Duo MFA', 'toolbar=no,location=no,directories=no,status=no,menubar=no,width=730,height=420')">Enroll Device</a><br /><br />
                          <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" name="continue" id="kc-continue" type="submit" value="Continue Login"/><br />
                    </div>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>