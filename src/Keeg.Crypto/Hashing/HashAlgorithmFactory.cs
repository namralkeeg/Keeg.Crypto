#region Copyright
/*
 * Copyright (C) 2018 Larry Lopez
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#endregion
using System;
using System.Collections.Concurrent;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;

namespace Keeg.Crypto.Hashing
{
    /// <summary>
    /// 
    /// </summary>
    public static class HashAlgorithmFactory
    {
        #region Instance Fields
        private static readonly Type classType;
        private static readonly Type[] constructorArgs;
        private static readonly ConcurrentDictionary<string, Type> classRegistry;
        private static readonly ConcurrentDictionary<string, ConstructorDelegate> classConstructors;

        private delegate HashAlgorithm ConstructorDelegate();
        #endregion

        /// <summary>
        /// 
        /// </summary>
        static HashAlgorithmFactory()
        {
            classType = typeof(HashAlgorithm);
            constructorArgs = new Type[] { };
            classRegistry = new ConcurrentDictionary<string, Type>();
            classConstructors = new ConcurrentDictionary<string, ConstructorDelegate>();

            var assembly = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
            var hashAlgorithms = from b in assembly.GetTypes()
                                 where !b.IsInterface 
                                 && !b.IsAbstract 
                                 && b.IsSubclassOf(classType)
                                 select b;

            foreach (var type in hashAlgorithms)
            {
                classRegistry.TryAdd(type.Name, type);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="identifier"></param>
        /// <returns></returns>
        public static HashAlgorithm Create(string identifier)
        {
            if (String.IsNullOrEmpty(identifier))
                throw new ArgumentException($"{nameof(identifier)} can not be null or empty", nameof(identifier));
            if (!classRegistry.ContainsKey(identifier))
                throw new ArgumentException($"No HashAlgorithm has been registered with the identifier: {identifier}", 
                    nameof(identifier));
            Contract.EndContractBlock();

            return Create(classRegistry[identifier]);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="type"></param>
        /// <returns></returns>
        private static HashAlgorithm Create(Type type)
        {
            if (type == null)
                throw new ArgumentNullException(nameof(type));
            Contract.EndContractBlock();

            if (classConstructors.TryGetValue(type.Name, out ConstructorDelegate del))
            {
                return del();
            }

            DynamicMethod dynamicMethod = new DynamicMethod("CreateInstance", classType, constructorArgs, type);
            ILGenerator ilGenerator = dynamicMethod.GetILGenerator();

            ilGenerator.Emit(OpCodes.Newobj, type.GetConstructor(constructorArgs));
            ilGenerator.Emit(OpCodes.Ret);

            del = (ConstructorDelegate)dynamicMethod.CreateDelegate(typeof(ConstructorDelegate));
            classConstructors.TryAdd(type.Name, del);
            return del();
        }
    }
}
