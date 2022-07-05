using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace SneddoBuilds.AspNetCore.JwtAuthApi
{
    public class ClaimsBuilder<T1, T2>: IClaimsBuilder<T1, T2>
    {
        public Func<T1, T2, IEnumerable<Claim>> builder { get; set; }
        public IEnumerable<Claim> Build(T1 input, T2 companyId)
        {
            return builder.Invoke(input, companyId);
        }
    }

    public interface IClaimsBuilder<T1, T2>
    {
        public Func<T1, T2, IEnumerable<Claim>> builder { get; set; }
        public IEnumerable<Claim> Build(T1 input, T2 companyId);
    }
}