using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.UI.Services;
using SendGrid;
using SendGrid.Helpers.Mail;
using SneddoBuilds.AspNetCore.JwtAuthApi.Models;

namespace SneddoBuilds.AspNetCore.JwtAuthApi.Services
{
    public class BasicSendGridEmailSender : IEmailSender
    {
        private readonly EmailSettings _emailSettings;
        
            public BasicSendGridEmailSender(EmailSettings emailSettings)
            {
                _emailSettings = emailSettings;
            }

            public Task SendEmailAsync(List<string> emails, string subject, string message)
            {
                return Execute(Environment.GetEnvironmentVariable("SENDGRID_KEY"), subject, message, emails);
            }

            public Task Execute(string apiKey, string subject, string message, List<string> emails)
            {
                var client = new SendGridClient(apiKey);
                var msg = new SendGridMessage()
                {
                    From = new EmailAddress(_emailSettings.FromEmail, _emailSettings.FromName),
                    Subject = subject,
                    PlainTextContent = message,
                    HtmlContent = message
                };

                foreach (var email in emails)
                {
                    msg.AddTo(new EmailAddress(email));
                }

                Task response = client.SendEmailAsync(msg);
                return response;
            }

            public async Task SendEmailAsync(string email, string subject, string htmlMessage)
            {
                await SendEmailAsync(new List<string>{email}, subject, htmlMessage);
            }
        }
}