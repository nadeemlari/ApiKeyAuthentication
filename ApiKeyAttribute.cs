using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace ApiKeyAuthentication
{
    [AttributeUsage(AttributeTargets.Class|AttributeTargets.Method)]
    public class ApiKeyAttribute : Attribute, IAsyncActionFilter
    {
        private const string ApiKeyHeaderName = "apikey";
        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            if (!context.HttpContext.Request.Headers.TryGetValue(ApiKeyHeaderName, out var apiKey))
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            var configuration = context.HttpContext.RequestServices.GetService<IConfiguration>();
            var validApiKey = configuration.GetValue<string>("ValidApiKey");
            if (!validApiKey.Equals(apiKey))
            {
                context.Result = new UnauthorizedResult();
                return;
            }
            await next();
        }
    }
}
