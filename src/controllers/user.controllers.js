const catchError = require('../utils/catchError');
const User = require('../models/User');
const EmailCode = require('../models/EmailCode');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { sendEmail } = require('../utils/sendEmail');

const getAll = catchError(async(req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async (req, res) => {
    const { password, email, firstName, frontBaseUrl } = req.body
    const hashedPassword = await bcrypt.hash(password, 10)
    const newBody = { ...req.body, password: hashedPassword }
    const result = await User.create(newBody);

    // GENERACIÓN DEL CÓDIGO PARA VERIFICAR EL EMAIL Y SE ALMACENA EN LA BASE DE DATOS JUNTO CON EL ID DEL USUARIO
    const code = require('crypto').randomBytes(64).toString('hex')
    await EmailCode.create({ code: code, userId: result.id })

    sendEmail({
      to: email,
      subject: 'Verificación de cuenta',
      html: `
      <div style="max-width: 500px; margin: 50px auto; background-color: #F8FAFC; padding: 30px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); font-family: 'Arial', sans-serif; color: #333333;">
        <h1 style="color: #007BFF; font-size: 28px; text-align: center; margin-bottom: 20px;">¡Hola ${firstName.toUpperCase()} :wave:!</h1>
        <p style="font-size: 18px; line-height: 1.6; margin-bottom: 25px; text-align: center;">Gracias por registrarte en nuestra aplicación. Para verificar su cuenta, haga clic en el siguiente enlace:</p>
        <div style="text-align: center;">
            <a href="${frontBaseUrl}/verify_email/${code}" style="display: inline-block; background-color: #007BFF; color: #FFFFFF; text-align: center; padding: 14px 28px; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 18px;">¡Verificar cuenta!</a>
        </div>
      </div>
  `
    })
    return res.status(201).json(result);
  });

const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.destroy({ where: {id} });
    if(!result) return res.sendStatus(404);
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;

    const fieldsToDelete = ["email", "password", "isVerifed"]
    fieldsToDelete.forEach(key => delete req.body[key]);

    const result = await User.update(
        req.body,
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const login = catchError(async(req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(401).json({ error: "Invalid credentials" })
  // VALIDAMOS QUE EL USUARIO TENGA UN EMAIL VERIFICADO
  if (!user.isVerifed) return res.status(401).json({ error: "Email not verified" })
  // SI EL USUARIO ES VALIDO, COMPARAMOS LA CONTRASEÑA
  const isValid = await bcrypt.compare(password, user.password)
  if (!isValid) return res.status(401).json({ error: "Invalid credentials" })
  // SI EL EMAIL ESTA VERIFICADO Y LA CONTRASEÑA ES VÁLIDA, GENERAMOS EL TOKEN DEL USUARIO Y LO ENVIAMOS
  const token = jwt.sign({ user }, process.env.TOKEN_SECRET, { expiresIn: '1d' })
  return res.json({ user, token })
})

const getMe = catchError(async (req, res) => {
  return res.json(req.user)
})

const verifyUser = catchError(async (req, res) => {
  const { code } = req.params;
  // BUSCAMOS EL CODIGO PARA RELACIONAR CON EL USUARIO
  const userCode = await EmailCode.findOne({ where: { code } })
  if (!userCode) return res.sendStatus(401)
  // BUSCAMOS EL USUARIO PARA VERIFICARLO
  const user = await User.findByPk(userCode.userId)
  if (!user) return res.sendStatus(401)
  // VERIFICAMOS AL USUARIO
  await user.update({ isVerifed: true })
  // ELIMINAMOS EL CÓDIGO DE VERIFICACIÓN DE LA BASE DE DATOS PARA QUE NO REPITAN EL PROCESO CON EL MISMO CODIGO
  await userCode.destroy()
  return res.status(201).json(user)
});

const resetPassword = catchError(async(req, res) => {
  const { email, frontBaseUrl } = req.body
  const user = await User.findOne({ where: { email } }) 
  if(!user) return res.sendStatus(404)
  // GENERACIÓN DEL CÓDIGO PARA VERIFICAR EL EMAIL Y SE ALMACENA EN LA BASE DE DATOS JUNTO CON EL ID DEL USUARIO
  const code = require('crypto').randomBytes(64).toString('hex')
  await EmailCode.create({ code: code, userId: user.id })

  sendEmail({
    to: email,
    subject: 'Cambio de contraseña',
    html: `
    <div style="max-width: 500px; margin: 50px auto; background-color: #F8FAFC; padding: 30px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); font-family: 'Arial', sans-serif; color: #333333;">
      <h1 style="color: #007BFF; font-size: 28px; text-align: center; margin-bottom: 20px;">¡Hola, recibimos una solicitud de cambio de contraseña!</h1>
      <p style="font-size: 18px; line-height: 1.6; margin-bottom: 25px; text-align: center;">Si no reconoces esta solicitud, haz caso omiso y elimina este email. Para proceder con el cambio de la contraseña, haga clic en el siguiente enlace:</p>
      <div style="text-align: center;">
          <a href="${frontBaseUrl}/reset_password/${code}" style="display: inline-block; background-color: #007BFF; color: #FFFFFF; text-align: center; padding: 14px 28px; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 18px;">¡Cambiar contraseña!</a>
      </div>
    </div>
`
  })
  return res.status(201).json(result);
})

const changePassword = catchError(async (req, res) => {
  const { code } = req.params;
  const { password } = req.body
  // BUSCAMOS EL CODIGO PARA RELACIONAR CON EL USUARIO
  const userCode = await EmailCode.findOne({ where: { code } })
  if (!userCode) return res.sendStatus(401)
  // BUSCAMOS EL USUARIO PARA VERIFICARLO
  const user = await User.findByPk(userCode.userId)
  if (!user) return res.sendStatus(401)
  // VALIDAMOS QUE EL USUARIO ESTÉ VERIFICADO
  if (!user.isVerifed) return res.status(401).json({ error: "Email not verified" })
  // CAMBIAMOS LA CONTRASEÑA DEL USUARIO
  const hashedPassword = await bcrypt.hash(password, 10)
  await user.update({ password: hashedPassword })
  // ELIMINAMOS EL CÓDIGO DE CAMBIO DE PASSWORD DE LA BASE DE DATOS PARA QUE NO REPITAN EL PROCESO CON EL MISMO CODIGO
  await userCode.destroy()
  return res.status(201).json(user)
})

module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    login,
    getMe,
    verifyUser,
    resetPassword,
    changePassword
}